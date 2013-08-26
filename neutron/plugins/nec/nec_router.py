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

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as q_exc
from neutron.common import utils
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.extensions import l3
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import constants as nconst
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import router as rdb
from neutron.plugins.nec.extensions import router_provider as ext_provider

LOG = logging.getLogger(__name__)

PROVIDER_L3AGENT = nconst.ROUTER_PROVIDER_L3AGENT
PROVIDER_OPENFLOW = nconst.ROUTER_PROVIDER_OPENFLOW

ROUTER_DRIVER_PATH = 'neutron.plugins.nec.nec_router.'
ROUTER_DRIVER_MAP = {
    PROVIDER_L3AGENT: ROUTER_DRIVER_PATH + 'RouterL3AgentDriver',
    PROVIDER_OPENFLOW: ROUTER_DRIVER_PATH + 'RouterOpenFlowDriver'
}

ROUTER_DRIVERS = {}

STATUS_ACTIVE = nconst.ROUTER_STATUS_ACTIVE
STATUS_ERROR = nconst.ROUTER_STATUS_ERROR


class RouterMixin(extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin):

    def create_router(self, context, router):
        """Create a new router entry on DB, and create it on OFC."""
        LOG.debug(_("RouterMixin.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        # NOTE: Needs to set up default security groups for a tenant here?
        # At the moment the default security group needs to be created
        # when the first network is created for the tenant.

        provider = get_provider_with_default(
            router['router'].get(ext_provider.ROUTER_PROVIDER))
        driver = get_driver_by_provider(provider)

        self._check_external_gateway_info(router['router'], driver)

        with context.session.begin(subtransactions=True):
            new_router = super(RouterMixin, self).create_router(context,
                                                                router)
            rdb.add_router_provider_binding(context.session,
                                            provider, str(new_router['id']))
            self._extend_router_dict_provider(new_router, provider)

        # create router on the network controller
        try:
            result = driver.create_router(context, tenant_id, new_router)
        except nexc.RouterOverLimit as e:
            super(RouterMixin, self).delete_router(context, new_router['id'])
            raise e
        if result:
            new_status = nconst.ROUTER_STATUS_ACTIVE
        else:
            new_status = nconst.ROUTER_STATUS_ERROR
        self._update_resource_status(context, "router", new_router['id'],
                                     new_status)
        return new_router

    def update_router(self, context, router_id, router):
        LOG.debug(_("RouterMixin.update_router() called, "
                    "id=%(id)s, router=%(router)s ."),
                  dict(id=router_id, router=router))

        with context.session.begin(subtransactions=True):
            #check if route exists and have permission to access
            old_router = super(RouterMixin, self).get_router(
                context, router_id)
            driver = self._get_router_driver_by_id(context, router_id)
            self._check_external_gateway_info(router['router'], driver)
            new_router = super(RouterMixin, self).update_router(
                context, router_id, router)
            driver.update_router(context, router_id,
                                 old_router, new_router)
        return new_router

    def delete_router(self, context, router_id):
        LOG.debug(_("RouterMixin.delete_router() called, id=%s."), router_id)

        router = super(RouterMixin, self).get_router(context, router_id)
        tenant_id = router['tenant_id']
        self._check_router_in_use(context, router_id)
        driver = self._get_router_driver_by_id(context, router_id)
        super(RouterMixin, self).delete_router(context, router_id)
        # TODO(amotoki): nec_router.delete_router should be called before
        # removing the router from the database?
        driver.delete_router(context, router_id, router)
        self._cleanup_ofc_tenant(context, tenant_id)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("RouterMixin.add_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))
        # Create intreface on DB
        # NOTE: policy check is done in super().add_router_interface()
        new_interface = super(RouterMixin, self).add_router_interface(
            context, router_id, interface_info)
        port_id = new_interface['port_id']
        port = self._get_port(context, port_id)
        subnet = self._get_subnet(context, new_interface['subnet_id'])
        port_info = {'network_id': port['network_id'],
                     'ip_address': port['fixed_ips'][0]['ip_address'],
                     'cidr': subnet['cidr'],
                     'mac_address': port['mac_address']}

        driver = self._get_router_driver_by_id(context, router_id)
        result = driver.add_interface(context, router_id, port_id, port_info)
        if result:
            new_status = nconst.ROUTER_STATUS_ACTIVE
        else:
            new_status = nconst.ROUTER_STATUS_ERROR
        self._update_resource_status(context, "port", port_id, new_status)
        return new_interface

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("RouterMixin.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))

        port_info = self._check_router_interface_port(context, router_id,
                                                      interface_info)
        driver = self._get_router_driver_by_id(context, router_id)

        driver.delete_interface(context, router_id, port_info['id'], port_info)
        # NOTE: If driver.delete_interface fails, raise an exception.
        # delete_port below is called only when delete_interface succeeds.
        return super(RouterMixin, self).remove_router_interface(
            context, router_id, interface_info)

    def _check_router_in_use(self, context, router_id):
        with context.session.begin(subtransactions=True):
            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {'device_id': [router_id],
                             'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=id)

    def _check_external_gateway_info(self, router, driver):
        """Check if external network is specified.

        The router implementation by PFC does not support the external network.
        If the external network is specified this method raises an exception.
        """
        if not driver.support_external_network:
            gw_info = router.get('external_gateway_info')
            if gw_info and gw_info.get('network_id'):
                raise nexc.RouterExternalGatewayNotSupported(
                    provider=PROVIDER_OPENFLOW)

    def _get_sync_routers(self, context, router_ids=None, active=None):
        """Query routers and their gw ports for l3 agent.

        The difference from the superclass in l3_db is that this method
        only lists routers hosted on l3-agents.
        """
        router_list = super(RouterMixin, self)._get_sync_routers(
            context, router_ids, active)
        if router_list:
            _router_ids = [r['id'] for r in router_list]
            agent_routers = rdb.get_routers_by_provider(
                context.session, 'l3-agent',
                router_ids=_router_ids)
            router_list = [r for r in router_list
                           if r['id'] in agent_routers]
        return router_list

    def _get_router_driver_by_id(self, context, router_id):
        provider = self._get_provider_by_router_id(context, router_id)
        return get_driver_by_provider(provider)

    def _get_provider_by_router_id(self, context, router_id):
        return rdb.get_provider_by_router(context.session, router_id)

    def _extend_router_dict_provider(self, router_res, provider):
        router_res[ext_provider.ROUTER_PROVIDER] = provider

    def extend_router_dict_provider(self, router_res, router_db):
        # NOTE: router_db.provider is None just after creating a router,
        # so we need to skip setting router_provider here.
        if not router_db.provider:
            return
        self._extend_router_dict_provider(router_res,
                                          router_db.provider['provider'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, [extend_router_dict_provider])


class L3AgentSchedulerDbMixin(agentschedulers_db.L3AgentSchedulerDbMixin):

    def auto_schedule_routers(self, context, host, router_ids):
        router_ids = rdb.get_routers_by_provider(
            context.session, nconst.ROUTER_PROVIDER_L3AGENT, router_ids)
        # If no l3-agent hosted router, there is no need to schedule.
        if not router_ids:
            return
        super(L3AgentSchedulerDbMixin, self).auto_schedule_routers(
            context, host, router_ids)

    def schedule_router(self, context, router):
        if (self._get_provider_by_router_id(context, router) ==
            nconst.ROUTER_PROVIDER_L3AGENT):
            super(L3AgentSchedulerDbMixin, self).schedule_router(
                context, router)

    def add_router_to_l3_agent(self, context, id, router_id):
        provider = self._get_provider_by_router_id(context, router_id)
        if provider != nconst.ROUTER_PROVIDER_L3AGENT:
            raise nexc.RouterProviderMismatch(
                router_id=router_id, provider=provider,
                expected_provider=nconst.ROUTER_PROVIDER_L3AGENT)
        super(L3AgentSchedulerDbMixin, self).add_router_to_l3_agent(
            context, id, router_id)


class L3AgentNotifyAPI(l3_rpc_agent_api.L3AgentNotifyAPI):

    def _notification(self, context, method, router_ids, operation, data):
        """Notify all the agents that are hosting the routers.

        _notication() is called in L3 db plugin for all routers regardless
        the routers are hosted on l3 agents or not. When the routers are
        not hosted on l3 agents, there is no need to notify.
        This method filters routers not hosted by l3 agents.
        """
        router_ids = rdb.get_routers_by_provider(
            context.session, nconst.ROUTER_PROVIDER_L3AGENT, router_ids)
        super(L3AgentNotifyAPI, self)._notification(
            context, method, router_ids, operation, data)


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
