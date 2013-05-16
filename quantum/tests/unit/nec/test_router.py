# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from quantum import manager
from quantum.tests.unit.nec import test_nec_plugin
from quantum.tests.unit import test_extension_extraroute as test_ext_route


class NecRouterTestCaseSkipFloatingIp(object):
    """Router test case for PFC based implementation."""

    def test_router_create_with_gwinfo(self):
        self.skipTest('No external gateway support')

    def test_router_add_gateway_dup_subnet2_returns_400(self):
        self.skipTest('No external gateway support')

    def test_router_add_gateway(self):
        self.skipTest('No external gateway support')

    def test_router_add_gateway_invalid_network_returns_404(self):
        self.skipTest('No external gateway support')

    def test_router_add_gateway_tenant_ctx(self):
        self.skipTest('No external gateway support')

    def test_router_delete_with_floatingip_existed_returns_409(self):
        self.skipTest('No external gateway support')

    def test_router_update_gateway(self):
        self.skipTest('No external gateway support')

    def test_router_update_gateway_with_existed_floatingip(self):
        self.skipTest('No external gateway support')

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        self.skipTest('No external gateway support')

    def test_network_update_external_failure(self):
        self.skipTest('No external gateway support')

    def test_network_update_external(self):
        self.skipTest('No external gateway support')

    def test_floatingip_crd_ops(self):
        self.skipTest('No external gateway support')

    def test_floatingip_with_assoc_fails(self):
        self.skipTest('No external gateway support')

    def test_floatingip_update(self):
        self.skipTest('No external gateway support')

    def test_floatingip_with_assoc(self):
        self.skipTest('No external gateway support')

    def test_floatingip_port_delete(self):
        self.skipTest('No external gateway support')

    def test_two_fips_one_port_invalid_return_409(self):
        self.skipTest('No external gateway support')

    def test_floating_ip_direct_port_delete_returns_409(self):
        self.skipTest('No external gateway support')

    def test_floatingip_list_with_port_id(self):
        self.skipTest('No external gateway support')

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest('No external gateway support')

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest('No external gateway support')

    def test_router_gateway_op_agent(self):
        self.skipTest('No external gateway support')

    def test_floatingips_op_agent(self):
        self.skipTest('No external gateway support')

    def test_l3_agent_routers_query_floatingips(self):
        self.skipTest('No external gateway support')

    def test_l3_agent_routers_query_gateway(self):
        self.skipTest('No external gateway support')

    # test_extension_extraroute
    def test_router_update_on_external_port(self):
        self.skipTest('No external gateway support')


class NecRouterL3AgentTestCase(test_ext_route.ExtraRouteDBTestCase):

    _plugin_name = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        ofc_manager_p = mock.patch(test_nec_plugin.OFC_MANAGER)
        ofc_manager_cls = ofc_manager_p.start()
        self.ofc = mock.Mock()
        ofc_manager_cls.return_value = self.ofc

        super(NecRouterL3AgentTestCase, self).setUp(self._plugin_name)
        plugin = manager.QuantumManager.get_plugin()
        plugin.network_scheduler = None
        plugin.router_scheduler = None


class NecRouterOpenFlowTestCase(NecRouterTestCaseSkipFloatingIp,
                                NecRouterL3AgentTestCase):
    pass
