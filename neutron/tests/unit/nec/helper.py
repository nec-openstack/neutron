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

import mock

OFC_MANAGER = 'neutron.plugins.nec.nec_plugin.ofc_manager.OFCManager'
NOTIFIER = 'neutron.plugins.nec.nec_plugin.NECPluginV2AgentNotifierApi'


class NecPluginMockMixin():
    def patch_remote_calls(self, use_stop=False):
        self.plugin_notifier_p = mock.patch(NOTIFIER)
        self.ofc_manager_p = mock.patch(OFC_MANAGER)
        self.plugin_notifier_p.start()
        self.ofc_manager_p.start()
        # When using mock.patch.stopall, we need to ensure
        # stop is not used anywhere in a single test.
        # In Neutron several tests use stop for each patched object,
        # so we need to take care of both cases.
        if use_stop:
            self.addCleanup(self.plugin_notifier_p.stop)
            self.addCleanup(self.ofc_manager_p.stop)
