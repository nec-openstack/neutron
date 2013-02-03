# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import mox
import unittest

from quantum.openstack.common import uuidutils
from quantum.plugins.nec.common import ofc_client as ofc
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec import drivers


class TestConfig(object):
    """Configuration for this test"""
    host = '127.0.0.1'
    port = 8888
    use_ssl = False
    key_file = None
    cert_file = None


def _ofc(id):
    """OFC ID converter"""
    return "ofc-%s" % id


class PFCDriverTestBase():

    driver = 'quantum.plugins.nec.drivers.pfc.PFCDriverBase'

    def setUp(self):
        self.mox = mox.Mox()
        self.driver = drivers.get_driver(self.driver)(TestConfig)
        self.mox.StubOutWithMock(ofc.OFCClient, 'do_request')

    def tearDown(self):
        self.mox.UnsetStubs()

    @staticmethod
    def get_ofc_item_random_params():
        """create random parameters for ofc_item test"""
        tenant_id = uuidutils.generate_uuid()
        network_id = uuidutils.generate_uuid()
        port_id = uuidutils.generate_uuid()
        portinfo = nmodels.PortInfo(id=port_id, datapath_id="0x123456789",
                                    port_no=1234, vlan_id=321,
                                    mac="11:22:33:44:55:66")
        return tenant_id, network_id, portinfo

    @staticmethod
    def _generate_ofc_tenant_id(tenant_id):
        fields = tenant_id.split('-')
        # Strip 1st character (UUID version) of 3rd field
        fields[2] = fields[2][1:]
        return ''.join(fields)

    @staticmethod
    def get_ofc_description(desc):
        """OFC description consists of [A-Za-z0-9_]."""
        return desc.replace('-', '_').replace(' ', '_')

    def _create_tenant(self, t, ofc_t, post_id=False, post_desc=False):
        tenant_path = '/tenants/%s' % ofc_t
        path = "/tenants"
        description = "desc of %s" % t
        body = {}
        if post_desc:
            ofc_description = self.get_ofc_description(description)
            body['description'] = ofc_description
        if post_id:
            body['id'] = ofc_t
            ofc.OFCClient.do_request("POST", path, body=body)
        else:
            ofc.OFCClient.do_request("POST", path, body=body).\
                AndReturn({'id': ofc_t})
        self.mox.ReplayAll()

        ret = self.driver.create_tenant(description, t)
        self.mox.VerifyAll()
        self.assertEqual(ret, tenant_path)

    def testa_create_tenant(self):
        t, n, p = self.get_ofc_item_random_params()
        ofc_t = self._generate_ofc_tenant_id(t)
        self._create_tenant(t, ofc_t)

    def testc_delete_tenant(self):
        t, n, p = self.get_ofc_item_random_params()

        path = "/tenants/%s" % _ofc(t)
        ofc.OFCClient.do_request("DELETE", path)
        self.mox.ReplayAll()

        self.driver.delete_tenant(path)
        self.mox.VerifyAll()

    def testd_create_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n
        ofc_description = self.get_ofc_description(description)

        tenant_path = "/tenants/%s" % _ofc(t)
        post_path = "%s/networks" % tenant_path
        body = {'description': ofc_description}
        network = {'id': _ofc(n)}
        ofc.OFCClient.do_request("POST", post_path, body=body).\
            AndReturn(network)
        self.mox.ReplayAll()

        ret = self.driver.create_network(tenant_path, description, n)
        self.mox.VerifyAll()
        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        self.assertEqual(ret, net_path)

    def teste_update_network(self):
        t, n, p = self.get_ofc_item_random_params()
        description = "desc of %s" % n
        ofc_description = self.get_ofc_description(description)

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        body = {'description': ofc_description}
        ofc.OFCClient.do_request("PUT", net_path, body=body)
        self.mox.ReplayAll()

        self.driver.update_network(_ofc(t), net_path, description)
        self.mox.VerifyAll()

    def testf_delete_network(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        ofc.OFCClient.do_request("DELETE", net_path)
        self.mox.ReplayAll()

        self.driver.delete_network(_ofc(t), net_path)
        self.mox.VerifyAll()

    def testg_create_port(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        post_path = "%s/ports" % net_path
        port_path = "/tenants/%s/networks/%s/ports/%s" % (_ofc(t), _ofc(n),
                                                          _ofc(p.id))
        body = {'datapath_id': p.datapath_id,
                'port': str(p.port_no),
                'vid': str(p.vlan_id)}
        port = {'id': _ofc(p.id)}
        ofc.OFCClient.do_request("POST", post_path, body=body).AndReturn(port)
        self.mox.ReplayAll()

        ret = self.driver.create_port(_ofc(t), net_path, p, p.id)
        self.mox.VerifyAll()
        self.assertEqual(ret, port_path)

    def testh_delete_port(self):
        t, n, p = self.get_ofc_item_random_params()

        net_path = "/tenants/%s/networks/%s" % (_ofc(t), _ofc(n))
        port_path = "/tenants/%s/networks/%s/ports/%s" % (_ofc(t), _ofc(n),
                                                          _ofc(p.id))
        ofc.OFCClient.do_request("DELETE", port_path)
        self.mox.ReplayAll()

        self.driver.delete_port(_ofc(t), net_path, port_path)
        self.mox.VerifyAll()


class PFCDriverBaseTest(PFCDriverTestBase, unittest.TestCase):
    pass


class PFCV3DriverTest(PFCDriverTestBase, unittest.TestCase):
    driver = 'pfc_v3'

    def testa_create_tenant(self):
        pass

    def testc_delete_tenant(self):
        pass


class PFCV4DriverTest(PFCDriverTestBase, unittest.TestCase):
    driver = 'pfc_v4'
