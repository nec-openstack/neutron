# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 NEC Corporation.  All rights reserved.
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

from quantum.common import utils
from quantum.openstack.common import importutils
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc

ROUTER_DRIVER_PATH = 'quantum.plugins.nec.router_driver.%s'
ROUTER_DRIVER_MAP = {'l3-agent': ROUTER_DRIVER_PATH % 'RouterL3AgentDriver',
                     'vrouter': ROUTER_DRIVER_PATH % 'RouterVRouterDriver'}

ROUTER_DRIVERS = {}


def load_router_driver(ofc_manager):
    enabled_flavors = (set(config.FLAVOR.router_flavors) &
                       set(ROUTER_DRIVER_MAP.keys()))
    for driver in enabled_flavors:
        driver_klass = importutils.import_class(ROUTER_DRIVER_MAP[driver])
        ROUTER_DRIVERS[driver] = driver_klass(ofc_manager)


def check_router_driver_enabled(flavor):
    return flavor in ROUTER_DRIVERS


def get_router_driver_by_flavor(flavor):
    return ROUTER_DRIVERS.get(flavor)


class RouterDriverBase(object):
    def __init__(self, ofc_manager):
        self.ofc = ofc_manager


class RouterL3AgentDriver(RouterDriverBase):
    pass


class RouterVRouterDriver(RouterDriverBase):
    def create_router(self, context, tenant_id, new_router):
        try:
            self.ofc.ensure_ofc_tenant(context, tenant_id)
            self.ofc.create_ofc_router(context, tenant_id,
                                       new_router['id'], new_router['name'])
            return True
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("create_router() failed due to %s") % exc
            LOG.error(reason)
            return False

    def update_router(self, context, router_id, old_router, new_router):
        self._update_ofc_routes(context, router_id,
                                old_router['routes'], new_router['routes'])

    def delete_router(self, context, router_id, router):
        try:
            self.ofc.delete_ofc_router(context, router_id, router)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_router() failed due to %s") % exc
            # NOTE: The OFC configuration of this network could be remained
            #       as an orphan resource. But, it does NOT harm any other
            #       resources, so this plugin just warns.
            LOG.warn(reason)

    def add_interface(self, context, router_id, port_id, port_info):
        try:
            self.ofc.add_ofc_router_interface(context, router_id,
                                              port_id, port_info)
            return True
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("add_router_interface() failed due to %s") % exc
            LOG.error(reason)
            return False

    def delete_interface(self, context, router_id, port_id, port_info):
        try:
            self.ofc.delete_ofc_router_interface(context, router_id, port_id,
                                                 port_info)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_router_interface() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "port", port_id,
                                         status.OperationalStatus.ERROR)
            # XXX(amotoki): Should coordinate an exception type
            # Internal Server Error will be returned now.
            raise exc

    def _update_ofc_routes(self, context, router_id, old_routes, new_routes):
        added, removed = utils.diff_list_of_dict(old_routes, new_routes)
        # NOTE(amotoki): route-update should be supported by PFC.
        # At the moment we need to remove an old route and then
        # add a new route. It may leads to no route for some destination
        # during route update.
        self.ofc.update_ofc_router_route(context, router_id,
                                         added, removed)
