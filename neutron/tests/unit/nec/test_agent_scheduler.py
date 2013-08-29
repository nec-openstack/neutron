# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 NEC Corporation.  All rights reserved.
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

from neutron.tests.unit.nec import helper
from neutron.tests.unit.nec import test_nec_plugin
from neutron.tests.unit.openvswitch import test_agent_scheduler


class NecAgentSchedulerTestCase(
    test_agent_scheduler.OvsAgentSchedulerTestCase,
    helper.NecPluginMockMixin):

    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        self.patch_remote_calls(use_stop=True)
        super(NecAgentSchedulerTestCase, self).setUp()


class NecDhcpAgentNotifierTestCase(
    test_agent_scheduler.OvsDhcpAgentNotifierTestCase,
    helper.NecPluginMockMixin):

    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        self.patch_remote_calls(use_stop=True)
        super(NecDhcpAgentNotifierTestCase, self).setUp()


class NecL3AgentNotifierTestCase(
    test_agent_scheduler.OvsL3AgentNotifierTestCase,
    helper.NecPluginMockMixin):

    plugin_str = test_nec_plugin.PLUGIN_NAME

    def setUp(self):
        self.patch_remote_calls(use_stop=True)
        super(NecL3AgentNotifierTestCase, self).setUp()
