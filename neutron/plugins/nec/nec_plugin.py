# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012-2013 NEC Corporation.  All rights reserved.
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
# @author: Akihiro MOTOKI

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.common import constants as const
from neutron.common import exceptions as q_exc
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import dhcp_rpc_base
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import l3_rpc_base
from neutron.db import portbindings_base
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import flavor as ext_flavor
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.openstack.common.rpc import proxy
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import constants as nconst
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec.db import router as rdb
from neutron.plugins.nec import nec_router
from neutron.plugins.nec import ofc_manager
from neutron.plugins.nec import packet_filter

LOG = logging.getLogger(__name__)


class NECPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                  extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin,
                  sg_db_rpc.SecurityGroupServerRpcMixin,
                  agentschedulers_db.L3AgentSchedulerDbMixin,
                  agentschedulers_db.DhcpAgentSchedulerDbMixin,
                  packet_filter.PacketFilterMixin,
                  portbindings_base.PortBindingBaseMixin):
    """NECPluginV2 controls an OpenFlow Controller.

    The Neutron NECPluginV2 maps L2 logical networks to L2 virtualized networks
    on an OpenFlow enabled network.  An OpenFlow Controller (OFC) provides
    L2 network isolation without VLAN and this plugin controls the OFC.

    NOTE: This is for Neutron API V2.  Codes for V1.0 and V1.1 are available
          at https://github.com/nec-openstack/neutron-openflow-plugin .

    The port binding extension enables an external application relay
    information to and from the plugin.
    """
    _supported_extension_aliases = ["agent",
                                    "binding",
                                    "dhcp_agent_scheduler",
                                    "ext-gw-mode",
                                    "extraroute",
                                    "flavor",
                                    "l3_agent_scheduler",
                                    "packet-filter",
                                    "quotas",
                                    "router",
                                    "security-group",
                                    ]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_if_noop_driver(aliases)
            self.remove_packet_filter_extension_if_disabled(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):

        ndb.initialize()
        self.ofc = ofc_manager.OFCManager()
        self.base_binding_dict = self._get_base_binding_dict()
        portbindings_base.register_port_dict_function()
        # Set the plugin default extension path
        # if no api_extensions_path is specified.
        if not config.CONF.api_extensions_path:
            config.CONF.set_override('api_extensions_path',
                                     'neutron/plugins/nec/extensions')

        self.setup_rpc()
        self.l3_rpc_notifier = L3AgentNotifyAPI()

        self.network_scheduler = importutils.import_object(
            config.CONF.network_scheduler_driver
        )
        self.router_scheduler = importutils.import_object(
            config.CONF.router_scheduler_driver
        )

        nec_router.load_driver(self.ofc)

    def setup_rpc(self):
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = NECPluginV2AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.agent_notifiers[const.AGENT_TYPE_L3] = L3AgentNotifyAPI()

        # NOTE: callback_sg is referred to from the sg unit test.
        self.callback_sg = SecurityGroupServerRpcCallback()
        callbacks = [NECPluginV2RPCCallbacks(self),
                     DhcpRpcCallback(),
                     L3RpcCallback(),
                     self.callback_sg,
                     agents_db.AgentExtRpcCallback()]
        self.dispatcher = q_rpc.PluginRpcDispatcher(callbacks)
        self.conn.create_consumer(self.topic, self.dispatcher, fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _update_resource_status(self, context, resource, id, status):
        """Update status of specified resource."""
        request = {'status': status}
        obj_getter = getattr(self, '_get_%s' % resource)
        with context.session.begin(subtransactions=True):
            obj_db = obj_getter(context, id)
            obj_db.update(request)

    def _check_ofc_tenant_in_use(self, context, tenant_id):
        """Return False if the specified tenant is not used."""
        # All networks are created on OFC
        filters = dict(tenant_id=[tenant_id])
        if self.get_networks_count(context, filters=filters):
            return True
        if rdb.get_router_count_by_flavor(context.session,
                                          nec_router.FLAVOR_OPENFLOW,
                                          tenant_id):
            return True
        return False

    def _cleanup_ofc_tenant(self, context, tenant_id):
        if not self._check_ofc_tenant_in_use(context, tenant_id):
            try:
                if self.ofc.exists_ofc_tenant(context, tenant_id):
                    self.ofc.delete_ofc_tenant(context, tenant_id)
                else:
                    LOG.debug(_('_cleanup_ofc_tenant: No OFC tenant for %s'),
                              tenant_id)
            except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                reason = _("delete_ofc_tenant() failed due to %s") % exc
                LOG.warn(reason)

    def activate_port_if_ready(self, context, port, network=None):
        """Activate port by creating port on OFC if ready.

        Conditions to activate port on OFC are:
            * port admin_state is UP
            * network admin_state is UP
            * portinfo are available (to identify port on OFC)
        """
        if not network:
            network = super(NECPluginV2, self).get_network(context,
                                                           port['network_id'])

        if not port['admin_state_up']:
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "port.admin_state_up is False."))
            return port
        elif not network['admin_state_up']:
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "network.admin_state_up is False."))
            return port
        elif not ndb.get_portinfo(context.session, port['id']):
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "no portinfo for this port."))
            return port
        elif self.ofc.exists_ofc_port(context, port['id']):
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "ofc_port already exists."))
            return port

        try:
            self.ofc.create_ofc_port(context, port['id'], port)
            port_status = const.PORT_STATUS_ACTIVE
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            LOG.error(_("create_ofc_port() failed due to %s"), exc)
            port_status = const.PORT_STATUS_ERROR

        if port_status is not port['status']:
            self._update_resource_status(context, "port", port['id'],
                                         port_status)
            port['status'] = port_status

        return port

    def deactivate_port(self, context, port):
        """Deactivate port by deleting port from OFC if exists."""
        if not self.ofc.exists_ofc_port(context, port['id']):
            LOG.debug(_("deactivate_port(): skip, ofc_port does not "
                        "exist."))
            return port

        try:
            self.ofc.delete_ofc_port(context, port['id'], port)
            port_status = const.PORT_STATUS_DOWN
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            LOG.error(_("delete_ofc_port() failed due to %s"), exc)
            port_status = const.PORT_STATUS_ERROR

        if port_status is not port['status']:
            self._update_resource_status(context, "port", port['id'],
                                         port_status)
            port['status'] = port_status

        return port

    def _net_status(self, network):
        # NOTE: NEC Plugin accept admin_state_up. When it's False, this plugin
        # deactivate all ports on the network to drop all packet and show
        # status='DOWN' to users. But the network is kept defined on OFC.
        if network['network']['admin_state_up']:
            return const.NET_STATUS_ACTIVE
        else:
            return const.NET_STATUS_DOWN

    def create_network(self, context, network):
        """Create a new network entry on DB, and create it on OFC."""
        LOG.debug(_("NECPluginV2.create_network() called, "
                    "network=%s ."), network)
        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        net_name = network['network']['name']
        net_id = uuidutils.generate_uuid()

        #set up default security groups
        self._ensure_default_security_group(context, tenant_id)

        network['network']['id'] = net_id
        network['network']['status'] = self._net_status(network)

        try:
            if not self.ofc.exists_ofc_tenant(context, tenant_id):
                self.ofc.create_ofc_tenant(context, tenant_id)
            self.ofc.create_ofc_network(context, tenant_id, net_id, net_name)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            LOG.error(_("failed to create network id=%(id)s on "
                        "OFC: %(exc)s"), {'id': net_id, 'exc': exc})
            network['network']['status'] = const.NET_STATUS_ERROR

        with context.session.begin(subtransactions=True):
            new_net = super(NECPluginV2, self).create_network(context, network)
            self._process_l3_create(context, new_net, network['network'])

        return new_net

    def update_network(self, context, id, network):
        """Update network and handle resources associated with the network.

        Update network entry on DB. If 'admin_state_up' was changed, activate
        or deactivate ports and packetfilters associated with the network.
        """
        LOG.debug(_("NECPluginV2.update_network() called, "
                    "id=%(id)s network=%(network)s ."),
                  {'id': id, 'network': network})

        if 'admin_state_up' in network['network']:
            network['network']['status'] = self._net_status(network)

        session = context.session
        with session.begin(subtransactions=True):
            old_net = super(NECPluginV2, self).get_network(context, id)
            new_net = super(NECPluginV2, self).update_network(context, id,
                                                              network)
            self._process_l3_update(context, new_net, network['network'])

        changed = (old_net['admin_state_up'] is not new_net['admin_state_up'])
        if changed and not new_net['admin_state_up']:
            # disable all active ports of the network
            filters = dict(network_id=[id], status=[const.PORT_STATUS_ACTIVE])
            ports = super(NECPluginV2, self).get_ports(context,
                                                       filters=filters)
            for port in ports:
                self.deactivate_port(context, port)
        elif changed and new_net['admin_state_up']:
            # enable ports of the network
            filters = dict(network_id=[id], status=[const.PORT_STATUS_DOWN],
                           admin_state_up=[True])
            ports = super(NECPluginV2, self).get_ports(context,
                                                       filters=filters)
            for port in ports:
                self.activate_port_if_ready(context, port, new_net)

        return new_net

    def delete_network(self, context, id):
        """Delete network and packet_filters associated with the network.

        Delete network entry from DB and OFC. Then delete packet_filters
        associated with the network. If the network is the last resource
        of the tenant, delete unnessary ofc_tenant.
        """
        LOG.debug(_("NECPluginV2.delete_network() called, id=%s ."), id)
        net = super(NECPluginV2, self).get_network(context, id)
        tenant_id = net['tenant_id']
        ports = self.get_ports(context, filters={'network_id': [id]})

        # check if there are any tenant owned ports in-use
        only_auto_del = all(p['device_owner'] in
                            db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS
                            for p in ports)
        if not only_auto_del:
            raise q_exc.NetworkInUse(net_id=id)

        # Make sure auto-delete ports on OFC are deleted.
        _error_ports = []
        for port in ports:
            port = self.deactivate_port(context, port)
            if port['status'] == const.PORT_STATUS_ERROR:
                _error_ports.append(port['id'])
        if _error_ports:
            reason = (_("Failed to delete port(s)=%s from OFC.") %
                      ','.join(_error_ports))
            raise nexc.OFCException(reason=reason)

        # delete all packet_filters of the network
        if self.packet_filter_enabled:
            filters = dict(network_id=[id])
            pfs = self.get_packet_filters(context, filters=filters)
            for pf in pfs:
                self.delete_packet_filter(context, pf['id'])

        try:
            self.ofc.delete_ofc_network(context, id, net)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_network() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "network", net['id'],
                                         const.NET_STATUS_ERROR)
            raise

        super(NECPluginV2, self).delete_network(context, id)

        self._cleanup_ofc_tenant(context, tenant_id)

    def _get_base_binding_dict(self):
        binding = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.CAPABILITIES: {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        return binding

    def create_port(self, context, port):
        """Create a new port entry on DB, then try to activate it."""
        LOG.debug(_("NECPluginV2.create_port() called, port=%s ."), port)

        port['port']['status'] = const.PORT_STATUS_DOWN

        port_data = port['port']
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            port = super(NECPluginV2, self).create_port(context, port)
            self._process_portbindings_create_and_update(context,
                                                         port_data,
                                                         port)
            self._process_port_create_security_group(
                context, port, sgids)
        self.notify_security_groups_member_updated(context, port)

        return self.activate_port_if_ready(context, port)

    def update_port(self, context, id, port):
        """Update port, and handle packetfilters associated with the port.

        Update network entry on DB. If admin_state_up was changed, activate
        or deactivate the port and packetfilters associated with it.
        """
        LOG.debug(_("NECPluginV2.update_port() called, "
                    "id=%(id)s port=%(port)s ."),
                  {'id': id, 'port': port})
        need_port_update_notify = False
        with context.session.begin(subtransactions=True):
            old_port = super(NECPluginV2, self).get_port(context, id)
            new_port = super(NECPluginV2, self).update_port(context, id, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         new_port)
            need_port_update_notify = self.update_security_group_on_port(
                context, id, port, old_port, new_port)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, old_port, new_port)
        if need_port_update_notify:
            self.notifier.port_update(context, new_port)

        changed = (old_port['admin_state_up'] != new_port['admin_state_up'])
        if changed:
            if new_port['admin_state_up']:
                new_port = self.activate_port_if_ready(context, new_port)
            else:
                new_port = self.deactivate_port(context, new_port)

        return new_port

    def delete_port(self, context, id, l3_port_check=True):
        """Delete port and packet_filters associated with the port."""
        LOG.debug(_("NECPluginV2.delete_port() called, id=%s ."), id)
        # ext_sg.SECURITYGROUPS attribute for the port is required
        # since notifier.security_groups_member_updated() need the attribute.
        # Thus we need to call self.get_port() instead of super().get_port()
        port = self.get_port(context, id)

        port = self.deactivate_port(context, port)
        if port['status'] == const.PORT_STATUS_ERROR:
            reason = _("Failed to delete port=%s from OFC.") % id
            raise nexc.OFCException(reason=reason)

        # delete all packet_filters of the port
        if self.packet_filter_enabled:
            filters = dict(port_id=[id])
            pfs = self.get_packet_filters(context, filters=filters)
            for packet_filter in pfs:
                self.delete_packet_filter(context, packet_filter['id'])

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, id)
            self._delete_port_security_group_bindings(context, id)
            super(NECPluginV2, self).delete_port(context, id)
        self.notify_security_groups_member_updated(context, port)

    # Router/ExtraRoute Extensions

    def create_router(self, context, router):
        """Create a new router entry on DB, and create it on OFC."""
        LOG.debug(_("NECPluginV2.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        # NOTE: Needs to set up default security groups for a tenant here?
        # At the moment the default security group needs to be created
        # when the first network is created for the tenant.

        flavor = nec_router.get_flavor_with_default(
            router['router'].get(ext_flavor.FLAVOR_ROUTER))
        driver = nec_router.get_driver_by_flavor(flavor)

        self._check_external_gateway_info(router['router'], driver)

        with context.session.begin(subtransactions=True):
            new_router = super(NECPluginV2, self).create_router(context,
                                                                router)
            rdb.add_router_flavor_binding(context.session,
                                          flavor, str(new_router['id']))
            self._extend_router_dict_flavor(context, new_router)

        # create router on the network controller
        try:
            result = driver.create_router(context, tenant_id, new_router)
        except nexc.RouterOverLimit as e:
            super(NECPluginV2, self).delete_router(context, new_router['id'])
            raise e
        if result:
            new_status = nec_router.STATUS_ACTIVE
        else:
            new_status = nec_router.STATUS_ERROR
        self._update_resource_status(context, "router", new_router['id'],
                                     new_status)
        return new_router

    def update_router(self, context, router_id, router):
        LOG.debug(_("NECPluginV2.update_router() called, "
                    "id=%(id)s, router=%(router)s ."),
                  dict(id=router_id, router=router))

        with context.session.begin(subtransactions=True):
            #check if route exists and have permission to access
            old_router = super(NECPluginV2, self).get_router(
                context, router_id)
            driver = self._get_router_driver_by_id(context, router_id)
            self._check_external_gateway_info(router['router'], driver)
            new_router = super(NECPluginV2, self).update_router(
                context, router_id, router)
            self._extend_router_dict_flavor(context, new_router)
            driver.update_router(context, router_id,
                                 old_router, new_router)
        return new_router

    def delete_router(self, context, router_id):
        LOG.debug(_("NECPluginV2.delete_router() called, id=%s."), router_id)

        router = super(NECPluginV2, self).get_router(context, router_id)
        tenant_id = router['tenant_id']
        # TODO(amotoki): Needs to be wrapped with a session
        self._check_router_in_use(context, router_id)
        driver = self._get_router_driver_by_id(context, router_id)
        super(NECPluginV2, self).delete_router(context, router_id)
        # TODO(amotoki): nec_router.delete_router should be called before
        # removing the router from the database?
        driver.delete_router(context, router_id, router)
        self._cleanup_ofc_tenant(context, tenant_id)

    def get_router(self, context, id, fields=None):
        router = super(NECPluginV2, self).get_router(context, id, fields)
        return self._extend_router_dict_flavor(context, router)

    def get_routers(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            routers = super(NECPluginV2, self).get_routers(context, filters,
                                                           fields)
            for router in routers:
                self._extend_router_dict_flavor(context, router)
        return routers

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("NECPluginV2.add_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))
        # Create intreface on DB
        # NOTE: policy check is done in super().add_router_interface()
        new_interface = super(NECPluginV2, self).add_router_interface(
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
            new_status = nec_router.STATUS_ACTIVE
        else:
            new_status = nec_router.STATUS_ERROR
        self._update_resource_status(context, "port", port_id, new_status)
        return new_interface

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("NECPluginV2.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  dict(id=router_id, interface=interface_info))

        port_info = self._check_router_interface_port(context, router_id,
                                                      interface_info)
        driver = self._get_router_driver_by_id(context, router_id)

        driver.delete_interface(context, router_id, port_info['id'], port_info)
        # NOTE: If driver.delete_interface fails, raise an exception.
        # delete_port below is called only when delete_interface succeeds.
        return super(NECPluginV2, self).remove_router_interface(
            context, router_id, interface_info)

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

    def _check_external_gateway_info(self, router, driver):
        """Check if external network is specified.

        The router implementation by PFC does not support the external network.
        If the external network is specified this method raises an exception.
        """
        if not driver.support_external_network:
            gw_info = router.get('external_gateway_info')
            if gw_info and gw_info.get('network_id'):
                raise nexc.RouterExternalGatewayNotSupported(
                    flavor=nec_router.FLAVOR_OPENFLOW)

    def _get_sync_routers(self, context, router_ids=None, active=None):
        """Query routers and their gw ports for l3 agent.

        The difference from the superclass in l3_db is that this method
        only lists routers hosted on l3-agents.
        """
        router_list = super(NECPluginV2, self)._get_sync_routers(
            context, router_ids, active)
        if router_list:
            _router_ids = [r['id'] for r in router_list]
            agent_routers = rdb.get_routers_by_flavor(
                context.session, 'l3-agent',
                router_ids=_router_ids)
            router_list = [r for r in router_list
                           if r['id'] in agent_routers]
        return router_list

    def _get_router_driver_by_id(self, context, router_id):
        flavor = self._get_flavor_by_router_id(context, router_id)
        return nec_router.get_driver_by_flavor(flavor)

    def _get_flavor_by_router_id(self, context, router_id):
        return rdb.get_flavor_by_router(context.session, router_id)

    def _extend_router_dict_flavor(self, context, router):
        flavor = self._get_flavor_by_router_id(context, router['id'])
        router[ext_flavor.FLAVOR_ROUTER] = flavor
        return router

    def auto_schedule_routers(self, context, host, router_ids):
        router_ids = rdb.get_routers_by_flavor(
            context.session, nconst.ROUTER_FLAVOR_L3AGENT, router_ids)
        # If no l3-agent hosted router, there is no need to schedule.
        if not router_ids:
            return
        super(NECPluginV2, self).auto_schedule_routers(context, host,
                                                       router_ids)

    def schedule_router(self, context, router):
        if (self._get_flavor_by_router_id(context, router) ==
            nconst.ROUTER_FLAVOR_L3AGENT):
            super(NECPluginV2, self).schedule_router(context, router)

    def add_router_to_l3_agent(self, context, id, router_id):
        flavor = self._get_flavor_by_router_id(context, router_id)
        if flavor != nconst.ROUTER_FLAVOR_L3AGENT:
            raise nexc.RouterProviderMismatch(
                router_id=router_id, flavor=flavor,
                expected_flavor=nconst.ROUTER_FLAVOR_L3AGENT)
        super(NECPluginV2, self).add_router_to_l3_agent(context, id, router_id)


class NECPluginV2AgentNotifierApi(proxy.RpcProxy,
                                  sg_rpc.SecurityGroupAgentRpcApiMixin):
    '''RPC API for NEC plugin agent.'''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(NECPluginV2AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_port_update = topics.get_topic_name(
            topic, topics.PORT, topics.UPDATE)

    def port_update(self, context, port):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port),
                         topic=self.topic_port_update)


class L3AgentNotifyAPI(l3_rpc_agent_api.L3AgentNotifyAPI):

    def _notification(self, context, method, router_ids, operation, data):
        """Notify all the agents that are hosting the routers.

        _notication() is called in L3 db plugin for all routers regardless
        the routers are hosted on l3 agents or not. When the routers are
        not hosted on l3 agents, there is no need to notify.
        This method filters routers not hosted by l3 agents.
        """
        router_ids = rdb.get_routers_by_flavor(context.session,
                                               nconst.ROUTER_FLAVOR_L3AGENT,
                                               router_ids)
        super(L3AgentNotifyAPI, self)._notification(
            context, method, router_ids, operation, data)


class DhcpRpcCallback(dhcp_rpc_base.DhcpRpcCallbackMixin):
    # DhcpPluginApi BASE_RPC_API_VERSION
    RPC_API_VERSION = '1.1'


class L3RpcCallback(l3_rpc_base.L3RpcCallbackMixin):
    # L3PluginApi BASE_RPC_API_VERSION
    RPC_API_VERSION = '1.0'


class SecurityGroupServerRpcCallback(
    sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    RPC_API_VERSION = sg_rpc.SG_RPC_VERSION

    @staticmethod
    def get_port_from_device(device):
        port = ndb.get_port_from_device(device)
        if port:
            port['device'] = device
        LOG.debug(_("NECPluginV2RPCCallbacks.get_port_from_device() called, "
                    "device=%(device)s => %(ret)s."),
                  {'device': device, 'ret': port})
        return port


class NECPluginV2RPCCallbacks(object):

    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self])

    def update_ports(self, rpc_context, **kwargs):
        """Update ports' information and activate/deavtivate them.

        Expected input format is:
            {'topic': 'q-agent-notifier',
             'agent_id': 'nec-q-agent.' + <hostname>,
             'datapath_id': <datapath_id of br-int on remote host>,
             'port_added': [<new PortInfo>,...],
             'port_removed': [<removed Port ID>,...]}
        """
        LOG.debug(_("NECPluginV2RPCCallbacks.update_ports() called, "
                    "kwargs=%s ."), kwargs)
        datapath_id = kwargs['datapath_id']
        session = rpc_context.session
        for p in kwargs.get('port_added', []):
            id = p['id']
            portinfo = ndb.get_portinfo(session, id)
            if portinfo:
                if (portinfo.datapath_id == datapath_id and
                    portinfo.port_no == p['port_no']):
                    LOG.debug(_("update_ports(): ignore unchanged portinfo in "
                                "port_added message (port_id=%s)."), id)
                    continue
                ndb.del_portinfo(session, id)
            ndb.add_portinfo(session, id, datapath_id, p['port_no'],
                             mac=p.get('mac', ''))
            port = self._get_port(rpc_context, id)
            if port:
                # NOTE: Make sure that packet filters on this port exist while
                # the port is active to avoid unexpected packet transfer.
                if portinfo:
                    self.plugin.deactivate_port(rpc_context, port)
                    self.plugin.deactivate_packet_filters_by_port(rpc_context,
                                                                  id)
                self.plugin.activate_packet_filters_by_port(rpc_context, id)
                self.plugin.activate_port_if_ready(rpc_context, port)
        for id in kwargs.get('port_removed', []):
            portinfo = ndb.get_portinfo(session, id)
            if not portinfo:
                LOG.debug(_("update_ports(): ignore port_removed message "
                            "due to portinfo for port_id=%s was not "
                            "registered"), id)
                continue
            if portinfo.datapath_id != datapath_id:
                LOG.debug(_("update_ports(): ignore port_removed message "
                            "received from different host "
                            "(registered_datapath_id=%(registered)s, "
                            "received_datapath_id=%(received)s)."),
                          {'registered': portinfo.datapath_id,
                           'received': datapath_id})
                continue
            ndb.del_portinfo(session, id)
            port = self._get_port(rpc_context, id)
            if port:
                self.plugin.deactivate_port(rpc_context, port)
                self.plugin.deactivate_packet_filters_by_port(rpc_context, id)

    def _get_port(self, context, port_id):
        try:
            return self.plugin.get_port(context, port_id)
        except q_exc.PortNotFound:
            return None
