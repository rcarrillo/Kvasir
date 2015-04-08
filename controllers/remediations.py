@auth.requires_login()
def add():
    """
    Add a remediation record to the database
    """
    fields = [
        'f_name',
        'f_description',
    ]
    db.t_hosts.f_engineer.default = auth.user.id
    response.title = "%s :: Add Remediation" % (settings.title)
    form=crud.create(db.t_remediations,next='detail/[id]', fields=fields)
    return dict(form=form)

@auth.requires_login()
def edit():
    record = db.t_remediations[request.args(0)] or redirect(URL('default', 'error', vars={'msg': T('Remediation record not found')}))
    response.title = "%s :: Update Remediation :: %s" % (settings.title, record.f_name)
    form=crud.update(db.t_remediations,record,next='read/[id]',
                     ondelete=lambda form: redirect(URL('list')))
    return dict(form=form)

@auth.requires_login()
def associate_vuln():
    response.title = "%s :: Associate a Vulnerability with a Remediation" % (settings.title)
    form=crud.create(db.t_vuln_remediations)
    return dict(form=form)

@auth.requires_login()
def remediations_by_host():
    """
    Returns a list of remediations based upon the vulnerabilities of
    (id, ipv4, ipv6)
    """
    record = get_host_record(request.args(0))
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    if request.extension == "json":

        aaData = []

        # Remediations for vulnerabilities affecting servicies on this host
        # including both applied and unapplied ones
        rows = db(
            (db.t_services.f_hosts_id==record.id) &
            (db.t_service_vulns.f_services_id==db.t_services.id) &
            (db.t_service_vulns.f_vulndata_id==db.t_vuln_remediations.f_vulndata_id) &
            (db.t_remediations.id==db.t_vuln_remediations.f_remediations_id)
        ).select(db.t_remediations.id, db.t_remediations.f_name,
                 db.t_remediations.f_description, db.t_applied_remediations.id,
                 db.t_applied_remediations.f_created_at, db.t_applied_remediations.f_user,
                 distinct=True,
            left=[db.t_applied_remediations.on(
                        (db.t_applied_remediations.f_hosts_id==record.id) &
                        (db.t_applied_remediations.f_remediations_id==db.t_remediations.id)
                     ),
                  db.t_applied_remediation_statuses.on(db.t_applied_remediation_statuses.id==db.t_applied_remediations.f_status_id)]
        )

        for row in rows:
            atxt = {}

            atxt['0'] = IMG(_src=URL(request.application,'static','images/details_open.png')).xml()
            atxt['1'] = row.t_remediations.f_name
            # Show link to detail if remediation is already applied, otherwise
            # display a button to apply it
            if row.t_applied_remediations.id:
                atxt['2'] = A(T('Details'), _href=URL('applied_detail.html', args=[row.t_applied_remediations.id]))
                atxt['3'] = 'at %s by %s' % (
                                row.t_applied_remediations.f_created_at.strftime('%H:%M:%S %d/%m/%Y'),
                                row.t_applied_remediations.f_user.username
                            )
            else:
                atxt['2'] = INPUT(_type='button', _class='apply_remediation', _value=T('Apply'))
                atxt['3'] = ''
            atxt['4'] = row.t_remediations.f_description
            atxt['DT_RowId'] = row.t_remediations.id

            aaData.append(atxt)

        result = { 'sEcho': request.vars._,
                   'iTotalRecords': len(aaData),
                   'aaData': aaData,
                   }

        return result

    form = TABLE(THEAD(TR(TH('', _width="5%"),
                          TH(T('Name')),
                          TH(T('Action')),
                          TH(T('Applied')),
                          )),
                 _class="datatable",
                 _id="remediationstable",
                 _style="width:100%")

    return dict(form=form, host=record)

@auth.requires_login()
def apply():
    """
    Apply a remediation to a host
    """

    record = db.t_remediations[request.args(0)]
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Remediation record not found')}))

    host_record = db.t_hosts[request.get_vars['f_hosts_id'] or request.post_vars['f_hosts_id']]
    if host_record is None:
        redirect(URL('default', 'error', vars={'msg': T('Host record not found')}))

    applied_rem_id = db.t_applied_remediations.insert(
        f_remediations_id=record.id,
        f_hosts_id=host_record.id
    )
    if applied_rem_id:
        # Redirect to the detail page to add comments or attachments
        redirect(URL('applied_detail', args=[applied_rem_id]))
    else:
        return 'error'

@auth.requires_login()
def applied_detail():

    record = db.t_applied_remediations[request.args(0)]
    if record is None:
        redirect(URL('default', 'error', vars={'msg': T('Applied remediation record not found')}))

    # Workaround for https://github.com/web2py/web2py/issues/606
    # https://groups.google.com/forum/#!topic/web2py/gdmRGC0lSTE
    # https://groups.google.com/forum/#!topic/web2py/FETaNdXhJZI
    import os
    db.t_applied_remediation_attachments.f_attachment.uploadfolder = os.path.join(request.folder,'uploads')

    form = SQLFORM.factory(
        db.t_applied_remediation_comments,
        db.t_applied_remediation_attachments,
        table_name='t_applied_remediation_attachments', # used to generate the directory name when uploadseparate is set
    )

    if form.process().accepted:
        if form.vars['f_text']:
            db.t_applied_remediation_comments.insert(
                f_applied_remediation=record.id,
                f_text=form.vars.f_text,
            )
        if form.vars['f_attachment']:
            db.t_applied_remediation_attachments.insert(
                f_applied_remediation=record.id,
                f_attachment=form.vars.f_attachment,
            )
    elif form.errors:
        # FIXME silent fail!
        pass

    comments = db(db.t_applied_remediation_comments.f_applied_remediation==record.id).select(
                   orderby=db.t_applied_remediation_comments.f_created_at,
               )
    attachments = db(db.t_applied_remediation_attachments.f_applied_remediation==record.id).select(
                      orderby=db.t_applied_remediation_attachments.f_created_at,
                  )

    i, j = 0, 0
    historial = []
    merge_up_to = min(len(comments), len(attachments))
    while i < merge_up_to and j < merge_up_to:
        if comments[i].f_created_at < attachments[j].f_created_at:
            historial.append(comments[i])
            i += 1
        else:
            historial.append(attachments[i])
            j += 1
    # At least one of boths is a zero-list
    historial += list(comments[i:]) + list(attachments[j:])

    host = db.t_hosts[record.f_hosts_id]
    remediation = db.t_remediations[record.f_remediations_id]

    response.title = "%s :: Remediation %s applied on %s by %s" % (
                        settings.title,
                        remediation.f_name,
                        host.f_hostname or host.f_ipaddr,
                        record.f_user.username,
                     )

    return dict(form=form, historial=historial)
