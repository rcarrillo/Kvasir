# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir Remediation Table Definitions
##
## Dynamic tables to manage the remediation of the
## vulnerabilities listed in Kvasir
##
## Author: Ramón Carrillo <racarrillo91@gmail.com>
##--------------------------------------#

########################################
## Task to complete ir order to remeditate one o more vulnerabilities
db.define_table('t_remediations',
    Field('id','id',represent=lambda id,row:SPAN(A(id,_href=URL('remediations' 'edit',args=id)))),
    Field('f_name', type='string', label=T('Name')),
    Field('f_description', type='text', length=65535, represent=lambda x, row: MARKMIN(x), label=T('Description')),
    format='%(f_name)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Associates a vulnerability to a remediation, meaning that such remediation
## fix or patch the vulnerability
db.define_table('t_vuln_remediations',
    Field('f_remediations_id', 'reference t_remediations', label=T('Remediation')),
    Field('f_vulndata_id', 'reference t_vulndata', label=T('Vulnerability')),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Status of and applied remediatons
db.define_table('t_applied_remediation_statuses',
    Field('f_name', 'string'),
    Field('f_level', 'integer'),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Remediations applied on a host
db.define_table('t_applied_remediations',
    Field('f_hosts_id', 'reference t_hosts'),
    Field('f_remediations_id', 'reference t_remediations'),
    Field('f_status_id', 'reference t_applied_remediation_statuses'),
    Field('f_created_at', 'datetime', default=request.now),
    Field('f_user', 'reference auth_user', default=auth.user_id),
    format=lambda r: A(T('applied remediation'), _href=URL('remediations', 'applied_detail', args=[r.id])),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Comments for applied remediations
db.define_table('t_applied_remediation_comments',
    Field('f_applied_remediation', 'reference t_applied_remediations', readable=False, writable=False),
    Field('f_text', type='text', length=65535, label=T('Comment')),
    Field('f_created_at', 'datetime', default=request.now, readable=False, writable=False),
    Field('f_user', 'reference auth_user', default=auth.user_id, readable=False, writable=False),
    format='%(f_text)s',
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Attachments for applied remediations
db.define_table('t_applied_remediation_attachments',
    Field('f_applied_remediation', 'reference t_applied_remediations', readable=False, writable=False),
    Field('f_attachment', 'upload', label=T('Attachment'), uploadseparate=True),
    Field('f_created_at', 'datetime', default=request.now, readable=False, writable=False),
    Field('f_user', 'reference auth_user', default=auth.user_id, readable=False, writable=False),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)
