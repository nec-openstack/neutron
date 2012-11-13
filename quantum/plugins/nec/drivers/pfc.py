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

import uuid

from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec import ofc_driver_base


class PFCDriverBase(ofc_driver_base.OFCDriverBase):

    def __init__(self, conf_ofc):
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port,
                                           use_ssl=conf_ofc.use_ssl,
                                           key_file=conf_ofc.key_file,
                                           cert_file=conf_ofc.cert_file)

    @classmethod
    def filter_supported(cls):
        return False

    def create_tenant(self, description, tenant_id=None):
        path = "/tenants"
        body = {'description': description}
        res = self.client.post(path, body=body)
        ofc_tenant_id = res['id']
        ofc_tenant_path = path + '/' + ofc_tenant_id
        return ofc_tenant_path

    def delete_tenant(self, ofc_tenant_id):
        path = ofc_tenant_id
        return self.client.delete(path)

    def create_network(self, ofc_tenant_id, description, network_id=None):
        path = "%s/networks" % ofc_tenant_id
        body = {'description': description}
        res = self.client.post(path, body=body)
        ofc_network_id = res['id']
        ofc_network_path = path + '/' + ofc_network_id
        return ofc_network_path

    def update_network(self, ofc_tenant_id, ofc_network_id, description):
        path = ofc_network_id
        body = {'description': description}
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

    PFC_ID_STRLEN_LIMIT = 31

    def create_tenant(self, description, tenant_id=None):
        path = "/tenants"
        ofc_tenant_id = tenant_id or str(uuid.uuid4())
        ofc_tenant_path = path + '/' + ofc_tenant_id[:self.PFC_ID_STRLEN_LIMIT]
        return ofc_tenant_path

    def delete_tenant(self, ofc_tenant_id):
        pass


class PFCV4Driver(PFCDriverBase):

    def create_tenant(self, description, tenant_id=None):
        ofc_tenant_id = tenant_id or str(uuid.uuid4())
        path = "/tenants"
        body = {'id': ofc_tenant_id,
                'description': description}
        res = self.client.post(path, body=body)
        ofc_tenant_id = res['id']
        ofc_tenant_path = path + '/' + ofc_tenant_id
        return ofc_tenant_path
