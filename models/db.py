# -*- coding: utf-8 -*-

##--------------------------------------#
## Kvasir
##
## (c) 2010-2014 Cisco Systems, Inc.
## (c) 2015 Kurt Grutzmacher
##
## Database configuration
##
## Author: Kurt Grutzmacher <grutz@jingojango.net>
##--------------------------------------#

from gluon.tools import Mail, Auth, Crud, Service, PluginManager
from gluon import current
from utils import web2py_uuid
import os

# Database settings
if 'db' in settings.kvasir_config:
    settings.migrate = settings.kvasir_config.get('db').get('migrate', True)
    settings.fake_migrate = settings.kvasir_config.get('db').get('fake_migrate', False)
    settings.database_uri = settings.kvasir_config.get('db').get('kvasir').get('uri')
    pool_size = settings.kvasir_config.get('db').get('kvasir').get('pool_size', 10)
    lazy_tables = settings.kvasir_config.get('db').get('lazy_tables', False)
    #settings.msfdb_uri = settings.kvasir_config.get('db').get('msf').get('uri')
else:
    settings.migrate = True
    settings.fake_migrate = False
    settings.database_uri = 'sqlite://kvasir.sqlite'
    pool_size = 5
    lazy_tables = False

if request.env.web2py_runtime_gae:            # if running on Google App Engine
    db = DAL('gae')                           # connect to Google BigTable
    session.connect(request, response, db = db) # and store sessions and tickets there
    ### or use the following lines to store sessions in Memcache
    # from gluon.contrib.memdb import MEMDB
    # from google.appengine.api.memcache import Client
    # session.connect(request, response, db = MEMDB(Client()))
else:                                         # else use a normal relational database
    db = DAL(settings.database_uri, check_reserved=['all'], lazy_tables=lazy_tables, pool_size=pool_size)

auth = Auth(db)                      # authentication/authorization
crud = Crud(db)                      # for CRUD helpers using auth
service = Service()                   # for json, xml, jsonrpc, xmlrpc, amfrpc
plugins = PluginManager()
#db._common_fields.append(auth.signature)

auth.settings.hmac_key = settings.kvasir_config.get('security_key') # before define_tables()
auth.settings.actions_disabled = [ 'register', 'request_reset_password', 'retrieve_username' ]
auth.settings.allow_basic_login=True
auth.settings.alternate_requires_registration = True
#crud.settings.auth = auth                      # =auth to enforce authorization on crud
current.auth = auth

from gluon.contrib.login_methods.ldap_auth import ldap_auth

auth.settings.login_methods = []

for m in settings.login_methods:
    if m == 'local':
        auth.settings.login_methods.append(auth)
    elif m == 'ldap':
        auth.settings.login_methods.append(ldap_auth(
            server=settings.login_config.get('ldap_server'),
            mode=settings.login_config.get('ldap_mode'),
            base_dn=settings.login_config.get('ldap_basedn'),
            bind_dn=settings.login_config.get('ldap_binddn'),
            bind_pw=settings.login_config.get('ldap_bindpw'),
        ))

response.generic_patterns = ['*.load', '*.json', '*.xml', '*.html', '*.csv']
response.combine_files = True
response.minify_files = True

##-------------------------------------------------------------------------
# logging

import logging, logging.handlers

def get_configured_logger(name):
    logger = logging.getLogger(name)
    if (len(logger.handlers) == 0):
        # This logger has no handlers, so we can assume it hasn't yet been configured
        formatter="%(asctime)s %(levelname)s %(process)s %(thread)s %(funcName)s():%(lineno)d %(message)s"
        logging.basicConfig(format=formatter, level=logging.DEBUG)

    return logger

# Assign application logger to a global var
logger = get_configured_logger(request.application)
