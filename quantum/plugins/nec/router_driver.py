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

import sys

from quantum.api.v2 import attributes as attr
from quantum.common import utils
from quantum.common import exceptions as q_exc
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import constants as nconst
from quantum.plugins.nec.common import exceptions as nexc

LOG = logging.getLogger(__name__)

ROUTER_DRIVER_PATH = 'quantum.plugins.nec.router_driver.%s'
ROUTER_DRIVER_MAP = {
    nconst.ROUTER_FLAVOR_L3AGENT: ROUTER_DRIVER_PATH % 'RouterL3AgentDriver',
    nconst.ROUTER_FLAVOR_OPENFLOW: ROUTER_DRIVER_PATH % 'RouterOpenFlowDriver'}

ROUTER_DRIVERS = {}


def load_driver(ofc_manager):
    if config.FLAVOR.default_router_flavor not in ROUTER_DRIVER_MAP:
        LOG.error(_('default_router_flavor %(default)s is supported! '
                    'Please specify one of %(supported)s'),
                  {'default': config.FLAVOR.default_router_flavor,
                   'supported': ROUTER_DRIVER_MAP.keys()})
        sys.exit(1)

    enabled_flavors = (set(config.FLAVOR.router_flavors +
                           [config.FLAVOR.default_router_flavor]) &
                       set(ROUTER_DRIVER_MAP.keys()))

    for driver in enabled_flavors:
        driver_klass = importutils.import_class(ROUTER_DRIVER_MAP[driver])
        ROUTER_DRIVERS[driver] = driver_klass(ofc_manager)

    if not ROUTER_DRIVERS:
        LOG.error(_('No router flavor is enabled. quantum-server terminated!'
                    ' (supported=%(supported)s, configured=%(config)s)'),
                  {'supported': ROUTER_DRIVER_MAP.keys(),
                   'config': config.FLAVOR.router_flavors})
        sys.exit(1)


def get_flavor_with_default(flavor):
    if not attr.is_attr_set(flavor):
        flavor = config.FLAVOR.default_router_flavor
    elif flavor not in ROUTER_DRIVERS:
        raise nexc.FlavorNotFound(flavor=flavor)
    return flavor


def get_driver_by_flavor(flavor):
    if flavor is None:
        flavor = config.FLAVOR.default_router_flavor
    elif flavor not in ROUTER_DRIVERS:
        raise nexc.FlavorNotFound(flavor=flavor)
    return ROUTER_DRIVERS[flavor]


class RouterDriverBase(object):
    def __init__(self, ofc_manager):
        self.ofc = ofc_manager

    def create_router(self, context, tenant_id, new_router):
        raise q_exc.NotImplementedError()

    def update_router(self, context, router_id, old_router, new_router):
        raise q_exc.NotImplementedError()

    def delete_router(self, context, router_id, router):
        raise q_exc.NotImplementedError()

    def add_interface(self, context, router_id, port_id, port_info):
        raise q_exc.NotImplementedError()

    def delete_interface(self, context, router_id, port_id, port_info):
        raise q_exc.NotImplementedError()


class RouterL3AgentDriver(RouterDriverBase):

    support_external_network = True

    def create_router(self, context, tenant_id, new_router):
        LOG.debug('RouterL3AgentDriver:create_router'
                  '(router=%s)', new_router)
        return True

    def update_router(self, context, router_id, old_router, new_router):
        LOG.debug('RouterL3AgentDriver:update_router'
                  '(id=%(id)s, router=%(router)s)',
                  {'id': router_id, 'router': new_router})
        return True

    def delete_router(self, context, router_id, router):
        LOG.debug('RouterL3AgentDriver:delete_router'
                  '(id=%(id)s, router=%(router)s)',
                  {'id': router_id, 'router': router})
        return True

    def add_interface(self, context, router_id, port_id, port_info):
        LOG.debug('RouterL3AgentDriver:add_interface'
                  '(id=%(id)s, port_id=%(port_id)s, port_info=%(port_info)s)',
                  {'id': router_id, 'port_id': port_id,
                   'port_info': port_info})
        return True

    def delete_interface(self, context, router_id, port_id, port_info):
        LOG.debug('RouterL3AgentDriver:delete_interface'
                  '(id=%(id)s, port_id=%(port_id)s, port_info=%(port_info)s)',
                  {'id': router_id, 'port_id': port_id,
                   'port_info': port_info})
        return True


class RouterOpenFlowDriver(RouterDriverBase):

    support_external_network = False

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
        return self._update_ofc_routes(context, router_id,
                                       old_router['routes'],
                                       new_router['routes'])

    def delete_router(self, context, router_id, router):
        try:
            self.ofc.delete_ofc_router(context, router_id, router)
            return True
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_router() failed due to %s") % exc
            # NOTE: The OFC configuration of this network could be remained
            #       as an orphan resource. But, it does NOT harm any other
            #       resources, so this plugin just warns.
            LOG.warn(reason)
            return False

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
            return True
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
        try:
            self.ofc.update_ofc_router_route(context, router_id,
                                             added, removed)
            return True
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("_update_ofc_routes() failed due to %s") % exc
            LOG.error(reason)
            return False
