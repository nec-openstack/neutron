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

import httplib

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as q_exc
from neutron.common import utils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import constants as nconst
from neutron.plugins.nec.common import exceptions as nexc

LOG = logging.getLogger(__name__)

PROVIDER_L3AGENT = nconst.ROUTER_PROVIDER_L3AGENT
PROVIDER_OPENFLOW = nconst.ROUTER_PROVIDER_OPENFLOW

ROUTER_DRIVER_PATH = 'neutron.plugins.nec.nec_router.%s'
ROUTER_DRIVER_MAP = {
    PROVIDER_L3AGENT: ROUTER_DRIVER_PATH % 'RouterL3AgentDriver',
    PROVIDER_OPENFLOW: ROUTER_DRIVER_PATH % 'RouterOpenFlowDriver'}

ROUTER_DRIVERS = {}

STATUS_ACTIVE = nconst.ROUTER_STATUS_ACTIVE
STATUS_ERROR = nconst.ROUTER_STATUS_ERROR


def load_driver(ofc_manager):

    if (PROVIDER_OPENFLOW in ROUTER_DRIVER_MAP and
        not ofc_manager.driver.router_supported()):
        LOG.warning(
            _('OFC does not support router with provider=%(provider)s, '
              'so removed it from supported provider '
              '(new router driver map=%(driver_map)s)'),
            {'provider': PROVIDER_OPENFLOW,
             'driver_map': ROUTER_DRIVER_MAP})
        del ROUTER_DRIVER_MAP[PROVIDER_OPENFLOW]

    if config.PROVIDER.default_router_provider not in ROUTER_DRIVER_MAP:
        LOG.error(_('default_router_provider %(default)s is supported! '
                    'Please specify one of %(supported)s'),
                  {'default': config.PROVIDER.default_router_provider,
                   'supported': ROUTER_DRIVER_MAP.keys()})
        sys.exit(1)

    enabled_providers = (set(config.PROVIDER.router_providers +
                             [config.PROVIDER.default_router_provider]) &
                         set(ROUTER_DRIVER_MAP.keys()))

    for driver in enabled_providers:
        driver_klass = importutils.import_class(ROUTER_DRIVER_MAP[driver])
        ROUTER_DRIVERS[driver] = driver_klass(ofc_manager)

    LOG.info(_('Enabled router drivers: %s'), ROUTER_DRIVERS.keys())

    if not ROUTER_DRIVERS:
        LOG.error(_('No router provider is enabled. neutron-server terminated!'
                    ' (supported=%(supported)s, configured=%(config)s)'),
                  {'supported': ROUTER_DRIVER_MAP.keys(),
                   'config': config.PROVIDER.router_providers})
        sys.exit(1)


def get_provider_with_default(provider):
    if not attr.is_attr_set(provider):
        provider = config.PROVIDER.default_router_provider
    elif provider not in ROUTER_DRIVERS:
        raise nexc.ProviderNotFound(provider=provider)
    return provider


def get_driver_by_provider(provider):
    if provider is None:
        provider = config.PROVIDER.default_router_provider
    elif provider not in ROUTER_DRIVERS:
        raise nexc.ProviderNotFound(provider=provider)
    return ROUTER_DRIVERS[provider]


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
            if (isinstance(exc, nexc.OFCException) and
                exc.status == httplib.CONFLICT):
                raise nexc.RouterOverLimit(provider=PROVIDER_OPENFLOW)
            else:
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
                                         STATUS_ERROR)
            raise

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
