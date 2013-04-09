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
#
# @author: Akihiro MOTOKI

from quantum.common import exceptions as qexception
from quantum.common import utils
from quantum.db import extraroute_db
from quantum.db import l3_db
from quantum.extensions import l3


class RouterExternalGatewayNotSupported(qexception.BadRequest):
    message = _("Router (flavor=vrouter) does not support an external network")


class NecRouterMixin(extraroute_db.ExtraRoute_db_mixin):

    def create_router(self, context, router):
        """Create a new router entry on DB, and create it on OFC."""
        LOG.debug(_("NECPluginV2.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        # NOTE: Needs to set up default security groups for a tenant here?
        # At the moment the default security group needs to be created
        # when the first network is created for the tenant.

        self._check_external_gateway_info(router['router'])

        # create router in DB
        # TODO(amotoki)
        # needs to extend attribute after supporting flavor extension
        with context.session.begin(subtransactions=True):
            new_router = super(NecRouterMixin, self).create_router(context,
                                                                   router)
            self._update_resource_status(context, "router", new_router['id'],
                                         OperationalStatus.BUILD)

        # create router on the network controller
        try:
            self.ofc.ensure_ofc_tenant(context, tenant_id)
            self.ofc.create_ofc_router(context, tenant_id,
                                       new_router['id'], new_router['name'])
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("create_router() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "router", new_net['id'],
                                         OperationalStatus.ERROR)
        else:
            self._update_resource_status(context, "router", new_net['id'],
                                         OperationalStatus.ACTIVE)
        return new_router

    def update_router(self, context, router_id, router):
        LOG.debug(_("NECPluginV2.update_router() called, "
                    "id=%(id)s, router=%(router)s ."),
                  dict(id=router_id, router=router))

        r = router['router']
        self._check_external_gateway_info(r)

        with context.session.begin(subtransactions=True):
            #check if route exists and have permission to access
            old_router = super(NecRouterMixin, self).get_router(
                context, router_id)
            new_router = super(NecRouterMixin, self).update_router(
                context, router_id, router)
            self._update_ofc_routes(context, old_router['routes'],
                                    new_router['routes'])
        return new_router

    def delete_router(self, context, router_id):
        LOG.debug(_("NECPluginV2.delete_router() called, id=%s."), router_id)

        router = super(NecRouterMixin, self).get_router(context, router_id):
        tenant_id = router['tenant_id']
        # Needs to be wrapped with a session
        self._check_router_in_use(context, router_id)
        super(NecRouterMixin, self).delete_router(context, router_id)
        try:
            self.ofc.delete_ofc_router(context, router_id, router)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_router() failed due to %s") % exc
            # NOTE: The OFC configuration of this network could be remained
            #       as an orphan resource. But, it does NOT harm any other
            #       resources, so this plugin just warns.
            LOG.warn(reason)
        self._cleanup_ofc_tenant(context, tenant_id)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("NECPluginV2.add_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))
        # Create intreface on DB
        # NOTE: policy check is done in super().add_router_interface()
        new_interface = super(NecRouterMixin, self).add_router_interface(
            context, router_id, interface_info)
        port_id = new_interface['port_id']
        port = self._get_port(context, port_id)
        try:
            self.ofc.add_router_interface(context, router_id, port_id, port)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("add_router_interface() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "port", port_id,
                                         OperationalStatus.ERROR)
        else:
            self._update_resource_status(context, "port", port_id,
                                         OperationalStatus.ACTIVE)
        return new_interface

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("NECPluginV2.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))

        # make sure router exists
        router = self._get_router(context, router_id)
        try:
            policy.enforce(context,
                           "extension:router:remove_router_interface",
                           self._make_router_dict(router))
        except q_exc.PolicyNotAuthorized:
            raise l3.RouterNotFound(router_id=router_id)

        port_info = self._get_router_interface_port(context, router_id,
                                                    interface_info)
        port_id = port_info['id']
        self._confirm_router_interface_not_in_use(
            context, router_id, port_info['subnet_id'])

        try:
            self.ofc.delete_router_interface(context, router_id, port_id,
                                             port_info)
            super(NecRouterMixin, self).delete_port(context, port_info['id'],
                                                    l3_port_check=False)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_router_interface() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "port", port_id,
                                         OperationalStatus.ERROR)
            # XXX(amotoki): Should coordinate an exception type
            # Internal Server Error will be returned now.
            raise

    def _check_router_in_use(self, context, router_id):
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

    def _check_external_gateway_info(self, router):
        """Check if external network is specified.

        vRouter router does not support the external network. If the external
        network is specified this method raises an exception."""

        if 'external_gateway_info' in router:
            gw_info = router['external_gateway_info']
            network_id = gw_info.get('network_id') if gw_info else None
            if network_id:
                raise RouterExternalGatewayNotSupported()

    def _update_ofc_routes(context, old_routes, new_routes):
        added, removed = utils.diff_list_of_dict(old_routes, new_routes)
        # NOTE(amotoki): route-update is supported by PFC.
        # Thus we need to remove an old route and then add a new route.
        for route in removed:
            LOG.debug(_("Removed OFC route entry is '%s'"), route)
            self.ofc.delete_ofc_router_interface(context, router_id,
                                                 port_id, port)
        for route in added:
            LOG.debug(_("Added OFC route entry is '%s'"), route)
            self.ofc.add_ofc_router_interface(context, router_id,
                                              port_id, port)

    def _check_tenant_not_in_use(self, context, tenant_id):
        """Return True if the specified tenant is not used."""
        filters = dict(tenant_id=[tenant_id])
        nets = self.get_networks(context, filters=filters)
        if super(NECPluginV2, self).get_networks(context, filters=filters):
            return False
        if super(NECPluginV2, self).get_routers(context, filters=filters):
            return False
        return True
