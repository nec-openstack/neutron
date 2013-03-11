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

import re
import uuid

from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec import ofc_driver_base


HEX_ELEM = '[0-9A-Fa-f]'
UUID_PATTERN = '-'.join([HEX_ELEM + '{8}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{4}', HEX_ELEM + '{4}',
                         HEX_ELEM + '{12}'])


class PFCDriverBase(ofc_driver_base.OFCDriverBase):
    """Base Class for PDC Drivers

    PFCDriverBase provides methods to handle PFC resources through REST API.
    This uses ofc resource path instead of ofc resource ID.
    """

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
        """Generate PFC acceptable String"""
        return re.sub(r'[^0-9a-zA-Z]', '_', raw_str)

    def _generate_pfc_id(self, id_str):
        """Generate ID on PFC

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
        except:
            return self._generate_pfc_str(id_str)[:31]

    def _generate_pfc_description(self, desc):
        """Generate Description on PFC

        Currently, PFC Description must be less than 128.
        """
        return self._generate_pfc_str(desc)[:127]

    def create_tenant(self, description, tenant_id=None):
        path = "/tenants"
        pfc_desc = self._generate_pfc_description(description)
        body = {'description': pfc_desc}
        res = self.client.post(path, body=body)
        ofc_tenant_id = res['id']
        ofc_tenant_path = path + '/' + ofc_tenant_id
        return ofc_tenant_path

    def delete_tenant(self, ofc_tenant_id):
        path = ofc_tenant_id
        return self.client.delete(path)

    def create_network(self, ofc_tenant_id, description, network_id=None):
        path = "%s/networks" % ofc_tenant_id
        pfc_desc = self._generate_pfc_description(description)
        body = {'description': pfc_desc}
        res = self.client.post(path, body=body)
        ofc_network_id = res['id']
        ofc_network_path = path + '/' + ofc_network_id
        return ofc_network_path

    def update_network(self, ofc_tenant_id, ofc_network_id, description):
        path = ofc_network_id
        pfc_desc = self._generate_pfc_description(description)
        body = {'description': pfc_desc}
        return self.client.put(path, body=body)

    def delete_network(self, ofc_tenant_id, ofc_network_id):
        path = ofc_network_id
        return self.client.delete(path)

    def create_port(self, ofc_tenant_id, ofc_network_id, portinfo,
                    port_id=None):
        path = "%s/ports" % ofc_network_id
        body = {'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        res = self.client.post(path, body=body)
        ofc_port_id = res['id']
        ofc_port_path = path + '/' + ofc_port_id
        return ofc_port_path

    def delete_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id):
        path = ofc_port_id
        return self.client.delete(path)


class PFCV3Driver(PFCDriverBase):

    def create_tenant(self, description, tenant_id=None):
        path = "/tenants"
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        ofc_tenant_path = path + '/' + ofc_tenant_id
        return ofc_tenant_path

    def delete_tenant(self, ofc_tenant_id):
        pass


class PFCV4Driver(PFCDriverBase):

    def create_tenant(self, description, tenant_id=None):
        path = "/tenants"
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        body = {'id': ofc_tenant_id}
        res = self.client.post(path, body=body)
        ofc_tenant_path = path + '/' + ofc_tenant_id
        return ofc_tenant_path
