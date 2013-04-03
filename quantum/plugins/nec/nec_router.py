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

from quantum.db import extraroute_db
from quantum.db import l3_db
from quantum.extensions import l3

class NecRouterMixin(extraroute_db.ExtraRoute_db_mixin):

    def create_router(self, context, router):
        """Create a new router entry on DB, and create it on OFC."""
        LOG.debug(_("NECPluginV2.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        # NOTE: Needs to set up default security groups for a tenant here?
        # At the moment the default security group needs to be created
        # when the first network is created for the tenant.

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
        pass

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
        port = self._get_port(context, new_interface['port_id'])
        # XXX: try/except
        self.ofc.add_router_interface(context, router_id, port)
        return new_interface

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("NECPluginV2.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))
        super(NecRouterMixin, self).remove_router_interface(context, router_id,
                                                         interface_info)

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

    def _check_tenant_not_in_use(self, context, tenant_id):
        """Return True if the specified tenant is not used."""
        filters = dict(tenant_id=[tenant_id])
        nets = self.get_networks(context, filters=filters)
        if super(NECPluginV2, self).get_networks(context, filters=filters):
            return False
        if super(NECPluginV2, self).get_routers(context, filters=filters):
            return False
        return True
