# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
# @author: Ryota MIBU
# @author: Akihiro MOTOKI

import re
import uuid

import netaddr

from neutron.api.v2 import attributes
from neutron.common import log as call_log
from neutron import manager
from neutron.plugins.nec.common import ofc_client
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec.extensions import packetfilter as ext_pf
from neutron.plugins.nec import ofc_driver_base


class PFCDriverBase(ofc_driver_base.OFCDriverBase):
    """Base Class for PDC Drivers.

    PFCDriverBase provides methods to handle PFC resources through REST API.
    This uses ofc resource path instead of ofc resource ID.

    The class implements the API for PFC V4.0 or later.
    """

    router_supported = False

    def __init__(self, conf_ofc):
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port,
                                           use_ssl=conf_ofc.use_ssl,
                                           key_file=conf_ofc.key_file,
                                           cert_file=conf_ofc.cert_file)

    @classmethod
    def filter_supported(cls):
        return False

    def _generate_pfc_str(self, raw_str):
        """Generate PFC acceptable String."""
        return re.sub(r'[^0-9a-zA-Z]', '_', raw_str)

    def _generate_pfc_id(self, id_str):
        """Generate ID on PFC.

        Currently, PFC ID must be less than 32.
        Shorten UUID string length from 36 to 31 by follows:
          * delete UUID Version and hyphen (see RFC4122)
          * ensure str length
        """
        try:
            # openstack.common.uuidutils.is_uuid_like() returns
            # False for KeyStone tenant_id, so uuid.UUID is used
            # directly here to accept tenant_id as UUID string
            uuid_str = str(uuid.UUID(id_str)).replace('-', '')
            uuid_no_version = uuid_str[:12] + uuid_str[13:]
            return uuid_no_version[:31]
        except Exception:
            return self._generate_pfc_str(id_str)[:31]

    def _generate_pfc_description(self, desc):
        """Generate Description on PFC.

        Currently, PFC Description must be less than 128.
        """
        return self._generate_pfc_str(desc)[:127]

    def _extract_ofc_network_id(self, ofc_network_id):
        # ofc_network_id : /tenants/<tenant-id>/networks/<network-id>
        return ofc_network_id.split('/')[4]

    def _extract_ofc_port_id(self, ofc_port_id):
        # ofc_port_id :
        # /tenants/<tenant-id>/networks/<network-id>/ports/<port-id>
        return ofc_port_id.split('/')[6]

    def create_tenant(self, description, tenant_id=None):
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        body = {'id': ofc_tenant_id}
        self.client.post('/tenants', body=body)
        return '/tenants/' + ofc_tenant_id

    def delete_tenant(self, ofc_tenant_id):
        return self.client.delete(ofc_tenant_id)

    def create_network(self, ofc_tenant_id, description, network_id=None):
        path = "%s/networks" % ofc_tenant_id
        pfc_desc = self._generate_pfc_description(description)
        body = {'description': pfc_desc}
        res = self.client.post(path, body=body)
        ofc_network_id = res['id']
        return path + '/' + ofc_network_id

    def delete_network(self, ofc_network_id):
        return self.client.delete(ofc_network_id)

    def create_port(self, ofc_network_id, portinfo,
                    port_id=None, filters=None):
        path = "%s/ports" % ofc_network_id
        body = {'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        if self.filter_supported and filters:
            body['filters'] = [self._extract_ofc_filter_id(pf[1])
                               for pf in filters]
        res = self.client.post(path, body=body)
        ofc_port_id = res['id']
        return path + '/' + ofc_port_id

    def delete_port(self, ofc_port_id):
        return self.client.delete(ofc_port_id)

    def convert_ofc_tenant_id(self, context, ofc_tenant_id):
        # If ofc_tenant_id starts with '/', it is already new-style
        if ofc_tenant_id[0] == '/':
            return ofc_tenant_id
        return '/tenants/%s' % ofc_tenant_id

    def convert_ofc_network_id(self, context, ofc_network_id, tenant_id):
        # If ofc_network_id starts with '/', it is already new-style
        if ofc_network_id[0] == '/':
            return ofc_network_id

        ofc_tenant_id = ndb.get_ofc_id_lookup_both(
            context.session, 'ofc_tenant', tenant_id)
        ofc_tenant_id = self.convert_ofc_tenant_id(context, ofc_tenant_id)
        params = dict(tenant=ofc_tenant_id, network=ofc_network_id)
        return '%(tenant)s/networks/%(network)s' % params

    def convert_ofc_port_id(self, context, ofc_port_id, tenant_id, network_id):
        # If ofc_port_id  starts with '/', it is already new-style
        if ofc_port_id[0] == '/':
            return ofc_port_id

        ofc_network_id = ndb.get_ofc_id_lookup_both(
            context.session, 'ofc_network', network_id)
        ofc_network_id = self.convert_ofc_network_id(
            context, ofc_network_id, tenant_id)
        params = dict(network=ofc_network_id, port=ofc_port_id)
        return '%(network)s/ports/%(port)s' % params


class PFCFilterDriverMixin(object):
    """PFC PacketFilter Driver Mixin."""
    filters_path = "/filters"
    filter_path = "/filters/%s"

    @classmethod
    def filter_supported(cls):
        return True

    def _generate_body(self, filter_dict, apply_ports=None, create=True):
        body = {}

        if create:
            # action : pass, drop (mandatory)
            if filter_dict['action'].upper() in ["ACCEPT", "ALLOW"]:
                body['action'] = "pass"
            else:
                body['action'] = "drop"
            # priority : 1-32766 (mandatory)
            body['priority'] = filter_dict['priority']

        for key in ['src_mac', 'dst_mac', 'src_port', 'dst_port']:
            if key in filter_dict:
                body[key] = filter_dict[key] or ""

        if 'src_mac' in filter_dict:
            body['src_mac'] = filter_dict['src_mac'] or ""

        if 'dst_mac' in filter_dict:
            body['dst_mac'] = filter_dict['dst_mac'] or ""

        for key in ['src_cidr', 'dst_cidr']:
            if key in filter_dict:
                if filter_dict[key]:
                    # CIDR must contain netmask even if it is an address.
                    body[key] = str(netaddr.IPNetwork(filter_dict[key]))
                else:
                    body[key] = ""

        # protocol : decimal (0-255)
        # eth_type : hex (0x0-0xFFFF)
        if 'protocol' in filter_dict:
            if not filter_dict['protocol']:
                body['protocol'] = ""
            elif filter_dict['protocol'].upper() == "ICMP":
                body['eth_type'] = "0x800"
                body['protocol'] = 1
            elif filter_dict['protocol'].upper() == "TCP":
                body['eth_type'] = "0x800"
                body['nw_proto'] = 6
            elif filter_dict['protocol'].upper() == "UDP":
                body['eth_type'] = "0x800"
                body['nw_proto'] = 17
            elif filter_dict['protocol'].upper() == "ARP":
                body['eth_type'] = "0x806"
            else:
                body['protocol'] = int(filter_dict['protocol'], 0)

        if 'eth_type' not in body and 'eth_type' in filter_dict:
            if filter_dict['eth_type']:
                body['eth_type'] = hex(filter_dict['eth_type'])
            else:
                body['eth_type'] = ""

        # apply_ports
        if apply_ports:
            body['apply_ports'] = [self._extract_ofc_port_id(p[1])
                                   for p in apply_ports]

        return body

    def _validate_filter_common(self, filter_dict):
        # Currently PFC support only IPv4 CIDR.
        for field in ['src_cidr', 'dst_cidr']:
            if (not filter_dict.get(field) or
                filter_dict[field] == attributes.ATTR_NOT_SPECIFIED):
                continue
            net = netaddr.IPNetwork(filter_dict[field])
            if net.version != 4:
                raise ext_pf.PacketFilterIpVersionNonSupported(
                    version=net.version, field=field, value=filter_dict[field])
        # priority should be 1-32766
        if ('priority' in filter_dict and
            not (1 <= filter_dict['priority'] <= 32766)):
            raise ext_pf.PacketFilterInvalidPriority(min=1, max=32766)

    def _validate_duplicate_priority(self, context, filter_dict):
        plugin = manager.NeutronManager.get_plugin()
        filters = {'network_id': [filter_dict['network_id']],
                   'priority': [filter_dict['priority']]}
        ret = plugin.get_packet_filters(context, filters=filters,
                                        fields=['id'])
        if ret:
            raise ext_pf.PacketFilterDuplicatedPriority(
                priority=filter_dict['priority'])

    def validate_filter_create(self, context, filter_dict):
        self._validate_filter_common(filter_dict)
        self._validate_duplicate_priority(context, filter_dict)

    def validate_filter_update(self, context, filter_dict):
        for field in ['action', 'priority']:
            if field in filter_dict:
                raise ext_pf.PacketFilterUpdateNotSupported(field=field)
        self._validate_filter_common(filter_dict)

    @call_log.log
    def create_filter(self, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None, apply_ports=None):
        body = self._generate_body(filter_dict, apply_ports, create=True)
        res = self.client.post(self.filters_path, body=body)
        # filter_id passed from a caller is not used.
        # ofc_filter_id is generated by PFC because the prefix of
        # filter_id has special meaning and it is internally used.
        ofc_filter_id = res['id']
        return self.filter_path % ofc_filter_id

    @call_log.log
    def update_filter(self, ofc_filter_id, filter_dict):
        body = self._generate_body(filter_dict, create=False)
        self.client.put(ofc_filter_id, body)

    def delete_filter(self, ofc_filter_id):
        return self.client.delete(ofc_filter_id)

    def _extract_ofc_filter_id(self, ofc_filter_id):
        # ofc_filter_id : /filters/<filter-id>
        return ofc_filter_id.split('/')[2]

    def convert_ofc_filter_id(self, context, ofc_filter_id):
        # PFC Packet Filter is supported after the format of mapping tables
        # are changed, so it is enough just to return ofc_filter_id
        return ofc_filter_id


class PFCRouterDriverMixin(object):

    router_supported = True
    router_nat_supported = False

    def create_router(self, ofc_tenant_id, router_id, description):
        path = '%s/routers' % ofc_tenant_id
        res = self.client.post(path, body=None)
        ofc_router_id = res['id']
        return path + '/' + ofc_router_id

    def delete_router(self, ofc_router_id):
        return self.client.delete(ofc_router_id)

    def add_router_interface(self, ofc_router_id, ofc_net_id,
                             ip_address=None, mac_address=None):
        # ip_address : <ip_address>/<netmask> (e.g., 10.0.0.0/24)
        path = '%s/interfaces' % ofc_router_id
        body = {'net_id': self._extract_ofc_network_id(ofc_net_id)}
        if ip_address:
            body['ip_address'] = ip_address
        if mac_address:
            body['mac_address'] = mac_address
        res = self.client.post(path, body=body)
        return path + '/' + res['id']

    def update_router_interface(self, ofc_router_inf_id,
                                ip_address=None, mac_address=None):
        # ip_address : <ip_address>/<netmask> (e.g., 10.0.0.0/24)
        if not ip_address and not mac_address:
            return
        body = {}
        if ip_address:
            body['ip_address'] = ip_address
        if mac_address:
            body['mac_address'] = mac_address
        return self.client.put(ofc_router_inf_id, body=body)

    def delete_router_interface(self, ofc_router_inf_id):
        return self.client.delete(ofc_router_inf_id)

    def list_router_routes(self, ofc_router_id):
        path = '%s/routes' % ofc_router_id
        ret = self.client.get(path)
        # Prepend ofc_router_id to route_id
        for r in ret['routes']:
            r['id'] = ofc_router_id + '/routes/' + r['id']
        return ret['routes']

    def add_router_route(self, ofc_router_id, destination, nexthop):
        path = '%s/routes' % ofc_router_id
        body = {'destination': destination,
                'nexthop': nexthop}
        ret = self.client.post(path, body=body)
        return path + '/' + ret['id']

    def delete_router_route(self, ofc_router_route_id):
        return self.client.delete(ofc_router_route_id)


class PFCV3Driver(PFCDriverBase):

    def create_tenant(self, description, tenant_id):
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        return "/tenants/" + ofc_tenant_id

    def delete_tenant(self, ofc_tenant_id):
        pass


class PFCV4Driver(PFCDriverBase):
    pass


class PFCV5Driver(PFCRouterDriverMixin, PFCDriverBase):
    pass


class PFCV51Driver(PFCFilterDriverMixin, PFCV5Driver):
    pass
