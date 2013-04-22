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

from quantum import context
from quantum.openstack.common import uuidutils
from quantum.plugins.nec.common import config
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels
from quantum.plugins.nec import ofc_manager
from quantum.tests import base


class OFCManagerTestBase(base.BaseTestCase):
    """Class conisting of OFCManager unit tests"""

    def setUp(self):
        super(OFCManagerTestBase, self).setUp()
        driver = "quantum.tests.unit.nec.stub_ofc_driver.StubOFCDriver"
        config.CONF.set_override('driver', driver, 'OFC')
        ndb.initialize()
        self.addCleanup(ndb.clear_db)
        self.ofc = ofc_manager.OFCManager()
        self.ofc.driver.enable_autocheck()
        self.ctx = context.get_admin_context()

    def get_random_params(self):
        """create random parameters for portinfo test"""
        tenant = uuidutils.generate_uuid()
        network = uuidutils.generate_uuid()
        port = uuidutils.generate_uuid()
        _filter = uuidutils.generate_uuid()
        none = uuidutils.generate_uuid()
        return tenant, network, port, _filter, none


class OFCManagerTest(OFCManagerTestBase):
    def testa_create_ofc_tenant(self):
        """test create ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_tenant', t))
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_tenant', t))
        tenant = ndb.get_ofc_item(self.ctx.session, 'ofc_tenant', t)
        self.assertEqual(tenant.ofc_id, "ofc-" + t[:-4])

    def testb_exists_ofc_tenant(self):
        """test exists_ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.assertFalse(self.ofc.exists_ofc_tenant(self.ctx, t))
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertTrue(self.ofc.exists_ofc_tenant(self.ctx, t))

    def testc_delete_ofc_tenant(self):
        """test delete ofc_tenant"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_tenant', t))
        self.ofc.delete_ofc_tenant(self.ctx, t)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_tenant', t))

    def testd_create_ofc_network(self):
        """test create ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_network', n))
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_network', n))
        network = ndb.get_ofc_item(self.ctx.session, 'ofc_network', n)
        self.assertEqual(network.ofc_id, "ofc-" + n[:-4])

    def teste_exists_ofc_network(self):
        """test exists_ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertFalse(self.ofc.exists_ofc_network(self.ctx, n))
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertTrue(self.ofc.exists_ofc_network(self.ctx, n))

    def testf_delete_ofc_network(self):
        """test delete ofc_network"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_network', n))
        self.ofc.delete_ofc_network(self.ctx, n, {'tenant_id': t})
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_network', n))

    def testg_create_ofc_port(self):
        """test create ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        ndb.add_portinfo(self.ctx.session, p, "0xabc", 1, 65535,
                         "00:11:22:33:44:55")
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_port', p))
        port = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_port(self.ctx, p, port)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_port', p))
        port = ndb.get_ofc_item(self.ctx.session, 'ofc_port', p)
        self.assertEqual(port.ofc_id, "ofc-" + p[:-4])

    def testh_exists_ofc_port(self):
        """test exists_ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        ndb.add_portinfo(self.ctx.session, p, "0xabc", 2, 65535,
                         "00:12:22:33:44:55")
        self.assertFalse(self.ofc.exists_ofc_port(self.ctx, p))
        port = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_port(self.ctx, p, port)
        self.assertTrue(self.ofc.exists_ofc_port(self.ctx, p))

    def testi_delete_ofc_port(self):
        """test delete ofc_port"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        ndb.add_portinfo(self.ctx.session, p, "0xabc", 3, 65535,
                         "00:13:22:33:44:55")
        port = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_port(self.ctx, p, port)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_port', p))
        self.ofc.delete_ofc_port(self.ctx, p, port)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_port', p))


class OFCManagerFilterTest(OFCManagerTestBase):
    def testj_create_ofc_packet_filter(self):
        """test create ofc_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session,
                                          'ofc_packet_filter', f))
        pf = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_packet_filter(self.ctx, f, pf)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session,
                                         'ofc_packet_filter', f))
        _filter = ndb.get_ofc_item(self.ctx.session, 'ofc_packet_filter', f)
        self.assertEqual(_filter.ofc_id, "ofc-" + f[:-4])

    def testk_exists_ofc_packet_filter(self):
        """test exists_ofc_packet_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertFalse(self.ofc.exists_ofc_packet_filter(self.ctx, f))
        pf = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_packet_filter(self.ctx, f, pf)
        self.assertTrue(self.ofc.exists_ofc_packet_filter(self.ctx, f))

    def testl_delete_ofc_packet_filter(self):
        """test delete ofc_filter"""
        t, n, p, f, none = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_network(self.ctx, t, n)
        pf = {'tenant_id': t, 'network_id': n}
        self.ofc.create_ofc_packet_filter(self.ctx, f, pf)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session,
                                         'ofc_packet_filter', f))
        self.ofc.delete_ofc_packet_filter(self.ctx, f)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session,
                                          'ofc_packet_filter', f))


class OFCManagerRouterTest(OFCManagerTestBase):
    def get_random_params(self):
        tenant = uuidutils.generate_uuid()
        router = uuidutils.generate_uuid()
        network = uuidutils.generate_uuid()
        return (tenant, router, network)

    def test_create_ofc_router(self):
        """test create ofc_router"""
        t, r, _n = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_router', r))
        self.ofc.create_ofc_router(self.ctx, t, r, 'test router')
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_router', r))
        router = ndb.get_ofc_item(self.ctx.session, 'ofc_router', r)
        self.assertEqual(router.ofc_id, "ofc-" + r[:-4])

    def test_exists_ofc_router(self):
        """test exists_ofc_router"""
        t, r, _n = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.assertFalse(self.ofc.exists_ofc_router(self.ctx, r))
        self.ofc.create_ofc_router(self.ctx, t, r)
        self.assertTrue(self.ofc.exists_ofc_router(self.ctx, r))

    def test_delete_ofc_router(self):
        """test delete ofc_router"""
        t, r, _n = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_router(self.ctx, t, r)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_router', r))
        self.ofc.delete_ofc_router(self.ctx, r, {'tenant_id': t})
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_network', r))

    def test_router_interface(self):
        t, r, n = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_router(self.ctx, t, r)
        self.ofc.create_ofc_network(self.ctx, t, n)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_router', r))
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_network', n))

        p = {'id': uuidutils.generate_uuid(),
             'network_id': n, 'ip_address': '10.1.1.1', 'cidr': '10.1.0.0/20',
             'mac_address': '11:22:33:44:55:66'}
        self.ofc.add_ofc_router_interface(self.ctx, r, p['id'], p)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session,
                                         'ofc_port', p['id']))
        self.ofc.delete_ofc_router_interface(self.ctx, r, p['id'], p)
        self.assertFalse(ndb.get_ofc_item(self.ctx.session,
                                          'ofc_port', p['id']))
        self.ofc.delete_ofc_router(self.ctx, r, {'tenant_id': t})
        self.assertFalse(ndb.get_ofc_item(self.ctx.session, 'ofc_network', r))

    def test_router_route(self):
        t, r, _n = self.get_random_params()
        self.ofc.create_ofc_tenant(self.ctx, t)
        self.ofc.create_ofc_router(self.ctx, t, r)
        self.assertTrue(ndb.get_ofc_item(self.ctx.session, 'ofc_router', r))

        added = [{'destination': '2.2.2.0/24', 'nexthop': '1.1.1.10'}]
        self.ofc.update_ofc_router_route(self.ctx, r, added_routes=added)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 1)

        added = [{'destination': '3.3.3.0/24', 'nexthop': '1.1.1.11'},
                 {'destination': '4.4.4.0/24', 'nexthop': '1.1.1.11'}]
        self.ofc.update_ofc_router_route(self.ctx, r, added_routes=added)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 3)

        removed = [{'destination': '2.2.2.0/24', 'nexthop': '1.1.1.10'}]
        self.ofc.update_ofc_router_route(self.ctx, r, removed_routes=removed)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 2)

        removed = [{'destination': '3.3.3.0/24', 'nexthop': '1.1.1.11'},
                   {'destination': '4.4.4.0/24', 'nexthop': '1.1.1.11'}]
        added = [{'destination': '5.5.5.0/24', 'nexthop': '1.1.1.12'}]
        self.ofc.update_ofc_router_route(self.ctx, r, added_routes=added,
                                         removed_routes=removed)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 1)

        removed = [{'destination': '5.5.5.0/24', 'nexthop': '1.1.1.12'}]
        self.ofc.update_ofc_router_route(self.ctx, r,
                                         removed_routes=removed)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 0)

        # If the specified entry does not exist, it is just ignored.
        removed = [{'destination': '2.2.2.0/24', 'nexthop': '1.1.1.10'}]
        self.ofc.update_ofc_router_route(self.ctx, r, removed_routes=removed)
        self.assertEqual(len(self.ofc.driver.ofc_router_route_dict), 0)


class OFCManagerTestWithOldMapping(OFCManagerTestBase):

    def setUp(self):
        super(OFCManagerTestWithOldMapping, self).setUp()
        # NOTE(amotoki): In OldMapping tests, DB entries are directly modified
        # to create a case where the old mapping tables are used intentionally.
        self.ofc.driver.disable_autocheck()

    def test_exists_ofc_tenant(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_tenant(self.ctx, t))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_tenant', t, ofc_t, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_tenant(self.ctx, t))

    def test_delete_ofc_tenant(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_tenant(self.ctx, t))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_tenant', t, ofc_t, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_tenant(self.ctx, t))

        self.ofc.delete_ofc_tenant(self.ctx, t)
        self.assertFalse(self.ofc.exists_ofc_tenant(self.ctx, t))

    def test_exists_ofc_network(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_network(self.ctx, n))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_network', n, ofc_n, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_network(self.ctx, n))

    def test_delete_ofc_network(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_network(self.ctx, n))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_network', n, ofc_n, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_network(self.ctx, n))

        net = {'tenant_id': t}
        self.ofc.delete_ofc_network(self.ctx, n, net)
        self.assertFalse(self.ofc.exists_ofc_network(self.ctx, n))

    def test_exists_ofc_port(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_port(self.ctx, p))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_port', p, ofc_p, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_port(self.ctx, p))

    def test_delete_ofc_port(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_port(self.ctx, p))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_port', p, ofc_p, old_style=True)
        self.assertTrue(self.ofc.exists_ofc_port(self.ctx, p))

        port = {'tenant_id': t, 'network_id': n}
        self.ofc.delete_ofc_port(self.ctx, p, port)
        self.assertFalse(self.ofc.exists_ofc_port(self.ctx, p))

    def test_exists_ofc_packet_filter(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_packet_filter(self.ctx, f))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_packet_filter', f, ofc_f,
                         old_style=True)
        self.assertTrue(self.ofc.exists_ofc_packet_filter(self.ctx, f))

    def test_delete_ofc_packet_filter(self):
        t, n, p, f, none = self.get_random_params()
        ofc_t, ofc_n, ofc_p, ofc_f, ofc_none = self.get_random_params()

        self.assertFalse(self.ofc.exists_ofc_packet_filter(self.ctx, f))

        session = self.ctx.session
        ndb.add_ofc_item(session, 'ofc_packet_filter', f, ofc_f,
                         old_style=True)
        self.assertTrue(self.ofc.exists_ofc_packet_filter(self.ctx, f))

        self.ofc.delete_ofc_packet_filter(self.ctx, f)
        self.assertFalse(self.ofc.exists_ofc_packet_filter(self.ctx, f))
