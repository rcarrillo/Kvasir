# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir Log Table Definitions
##
## Dynamic tables to keep track of changes in
## relevant tables of Kvasir
##
## Author: Ramón Carrillo <racarrillo91@gmail.com>
##--------------------------------------#

########################################
## Specify the output format of a log
db.define_table('t_log_types',
    Field('f_name', 'string'),
    Field('f_format', 'text'),
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

########################################
## Nice formatting for host log eventes
def host_log_format(r):
    import json

    fmt = db.t_log_types[r.f_type_id].f_format

    values = json.loads(r.f_values)
    output = {}

    import string
    for _, field, _, _ in string.Formatter().parse(fmt):
        if field is not None:
            if db.has_key(field) and values.has_key(field):
                # It contains a table name, then use the _format of
                # it to get te string representation
                table = db[field]

                # The record id is in the values
                record = table[values[field]]

                output[field] = table._format(record) if table._format else str(record)

            elif field in ('user',):
                # It contains a predefined value with a static and well
                # known representation
                if field == 'user':
                    output['user'] = SPAN(db.auth_user[r.f_user].username, _class='label')
            elif values.has_key(field): # It contains values defined in the log record
                output[field] = values[field]
            else:
                # Can't parse
                output[field] = '¿%s?' % field

    return fmt.format(**output)

########################################
## Keep track of hosts changes
## The values are a list of key-values that will be
## showed using the log type format.
db.define_table('t_host_logs',
    Field('f_hosts_id', 'reference t_hosts'),
    Field('f_event_time', 'datetime', default=request.now),
    Field('f_user', 'reference auth_user', default=auth.user_id),
    Field('f_type_id', 'reference t_hosts'),
    Field('f_values', 'json'),
    format=host_log_format,
    fake_migrate=settings.fake_migrate, migrate=settings.migrate)

# Register event types
def register_log(table, signal, output_format):
    def wrap(callback):

        # All this code will be executed at decoration time

        signals = [
            '_before_insert',
            '_after_insert',
            '_before_update',
            '_after_update',
            '_before_delete',
            '_after_delete',
        ]

        if signal not in signals:
            raise ValueError('Invalid signal: %s' % signal)

        event_name = '%s%s' % (table, signal)

        # Insert or update event type by evet name and get the id. The id will be
        # used bellow in save_record to create log of this type
        event_type = db(db.t_log_types.f_name==event_name).select().first()
        if not event_type:
            event_type_id = db.t_log_types.insert(f_name=event_name, f_format=output_format)
        else:
            event_type.update_record(f_format=output_format)
            event_type_id = event_type.id

        def save_record(*args):
            # Callback must return a 2-tuple containg the hosts and log values
            host, values = callback(*args)
            if not host and not values:
                return

            # A new log record is created
            import json
            db.t_host_logs.insert(
                f_hosts_id=host,
                f_type_id=event_type_id, # Closure
                f_values=json.dumps(values),
            )

        # Call the generated function when the signal is triggered
        db[table][signal].append(save_record)

        # Dumb callable, functions decorated with register_log aren't intended
        # to be called.
        return lambda: None # Dumb callable,

    return wrap

o_format = T('{user} applied remediation')
@register_log('t_applied_remediations', '_after_insert', o_format)
def log_insert_applied_remediation(f, id):
    return f.f_hosts_id, None

o_format = T('{user} changed remediation status to {status}')
@register_log('t_applied_remediations', '_after_update', o_format)
def log_update_applied_remediation(s, f):
    for field in f.keys():
        if field == 'f_status_id':
            status = t_applied_remediation_statuses[f.f_status_id].f_name
            return f.f_hosts_id, {'status': status}
    return None, None

o_format = T('{user} commented applied remediation {t_applied_remediations}')
@register_log('t_applied_remediation_comments', '_after_insert', o_format)
def log_insert_applied_remediation_comments(f, id):
    host_id = db.t_applied_remediations[f.f_applied_remediation].f_hosts_id
    return host_id, {'t_applied_remediations': f.f_applied_remediation}

o_format = T('{user} attached a file on applied remediation {t_applied_remediations}')
@register_log('t_applied_remediation_attachments', '_after_insert', o_format)
def log_insert_applied_remediation_attachments(f, id):
    host_id = db.t_applied_remediations[f.f_applied_remediation].f_hosts_id
    return host_id, {'t_applied_remediations': f.f_applied_remediation}
