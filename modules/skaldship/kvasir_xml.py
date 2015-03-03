# encoding: utf-8
"""
##--------------------------------------#
## Kvasir
##
## Importing Kvasir XML
##
## Author: Ramón Carrillo <rcarrillo91@gmail.com>
##--------------------------------------#
"""
from gluon import current
from skaldship.log import log
import logging

db = current.globalenv['db']
cache = current.globalenv['cache']
settings = current.globalenv['settings']
session = current.globalenv['session']


##-------------------------------------------------------------------------
from copy import copy
from xml.sax.handler import ContentHandler

class KvasirXMLParser(ContentHandler):

    def __init__(self):
        self.current_tag = None
        self.current_attrs = None

        self.host = None
        self.service = None
        self.service_info = None
        self.vuln = None
        self.vuln_data = None
        self.service_vuln = None

        self.count = 0

    def _translate_attr(self, attr):
        """
        Translate the attribute name from the XML to the equivalent field name
        in the table
        """

        if self.current_entity == 'host':
            if attr == 'netbios':
                return 'f_netbios_name'
            elif attr == 'assetgroup':
                return 'f_asset_group'

        return "f_%s" % attr

    def _parse_attrs(self, attrs):
        """
        Create a dict from the XML attributes. The keys of the dictionary will
        have the respective field name
        """
        attrs_dict = {}

        for key in attrs.keys():
            field = self._translate_attr(key)
            attrs_dict[field] = copy(attrs[key])

        return attrs_dict

    def startElement(self, name, attrs):
        self.current_tag = name

        if name in ('host', 'service', 'config', 'vuln'):
            self.current_entity = name
            self.current_attrs = self._parse_attrs(attrs)

        if name == "host":
            db.t_hosts.update_or_insert(
                db.t_hosts.f_ipaddr==self.current_attrs['f_ipaddr'],
                **self.current_attrs
            )
            db.commit()

            self.host = db(
                db.t_hosts.f_ipaddr==self.current_attrs['f_ipaddr']
            ).select().first()

        elif name == "service":
            if not self.host:
                raise Exception('Bad XML')

            if 'f_proto' not in self.current_attrs or 'f_number' not in self.current_attrs:
                raise Exception('Bad XML')

            db.t_services.update_or_insert(
                (db.t_services.f_proto==self.current_attrs['f_proto']) &
                (db.t_services.f_number==self.current_attrs['f_number']) &
                (db.t_services.f_hosts_id==self.host.id),
                f_hosts_id=self.host.id,
                **self.current_attrs
            )
            db.commit()

            self.service = db(
                (db.t_services.f_proto==self.current_attrs['f_proto']) &
                (db.t_services.f_number==self.current_attrs['f_number']) &
                (db.t_services.f_hosts_id==self.host.id)
            ).select().first()

        elif name == 'config':

            if not self.service:
                raise Exception('Bad XML')

            db.t_service_info.update_or_insert(
                f_name=self.current_attrs['f_name'],
                f_services_id=self.service.id
            )

            self.service_info = db(
                (db.t_service_info.f_name==self.current_attrs['f_name']) &
                (db.t_service_info.f_services_id==self.service.id)
            ).select().first()

        elif name == "vuln":
            db.t_vulndata.update_or_insert(f_vulnid=self.current_attrs['f_id'])

            self.vuln_data = db(
                db.t_vulndata.f_vulnid==self.current_attrs['f_id']
            ).select().first()

            if not self.service:
                # Vulnerability data
                if 'f_title' in self.current_attrs:
                    self.vuln_data.update_record(
                        f_title=self.current_attrs['f_title'],
                        f_severity=int(self.current_attrs['f_severity']),
                        f_pci_sev=int(self.current_attrs['f_pci_sev']),
                        f_cvss_score=float(self.current_attrs['f_cvss_score']),
                    )
                db.commit()

                self.count += 1

            else:
                # Vulnerable service
                db.t_service_vulns.update_or_insert(
                    f_services_id=self.service.id,
                    f_vulndata_id=self.vuln_data.id
                )

                self.service_vuln = db(
                    db.t_service_vulns.f_services_id==self.service.id,
                    db.t_service_vulns.f_vulndata_id==self.vuln_data.id
                ).select().first()

                self.service_vuln.update_record(
                    f_status=self.current_attrs['f_status']
                )

        elif name == 'os':
            pass


    def characters(self, content):

        if self.service:
            # Service info
            if self.service_info:
                self.service_info.update_record(f_text=content)
            # Vulnerable service
            elif self.service_vuln:
                if self.current_tag == 'proof':
                    self.service_vuln.update_record(f_proof=content)
            else:
                if self.current_tag == 'name':
                    self.service.update_record(f_name=content)
                elif self.current_tag == 'banner':
                    self.service.update_record(f_banner=content)

        if self.vuln_data:
            if self.current_tag == 'description':
                self.vuln_data.update_record(f_description=content)
            if self.current_tag == 'solution':
                self.vuln_data.update_record(f_solution=content)

    def endElement(self, name):
        self.current_tag = None

        if name in ('host', 'service', 'vuln'):
            self.current_attrs = None

        if name == 'host':
            self.host = None
        elif name == 'service':
            self.service = None
        elif name == 'config':
            self.service_info = None
        elif name == 'vuln':
            self.vuln = None
            self.vuln_data = None

def process_xml(filename, engineer):

    import xml.sax
    from skaldship.hosts import do_host_status

    log(" [*] Processing Kvasir XML file %s" % filename)

    kvasir_xml_parser = KvasirXMLParser()

    parser = xml.sax.make_parser()
    parser.setContentHandler(kvasir_xml_parser)
    parser.parse(open(filename))

    do_host_status()

    return kvasir_xml_parser
