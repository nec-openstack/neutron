# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_exc

from neutron.db import l3_db
from neutron.db import models_v2
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class RouterProvider(models_v2.model_base.BASEV2):
    """Represents a binding of router_id to flavor."""
    flavor = sa.Column(sa.String(255))
    router_id = sa.Column(sa.String(36), sa.ForeignKey('routers.id',
                                                       ondelete="CASCADE"),
                          primary_key=True)

    router = orm.relationship(l3_db.Router, uselist=False)
    #router = orm.relationship(l3_db.Router, uselist=False,
    #                          backref=orm.backref('flavor', uselist=False,
    #                                              cascade='delete'))

    def __repr__(self):
        return "<RouterProvider(%s,%s)>" % (self.flavor, self.router_id)


def _get_router_flavors_query(query, flavor=None, router_ids=None):
    if flavor:
        query = query.filter_by(flavor=flavor)
    if router_ids:
        column = RouterProvider.router_id
        query = query.filter(column.in_(router_ids))
    return query


def get_router_flavors(session, flavor=None, router_ids=None):
    """Retrieve a list of a pair of router ID and its flavor."""
    query = session.query(RouterProvider)
    query = _get_router_flavors_query(query, flavor, router_ids)
    return [{'flavor': x.flavor, 'router_id': x.router_id}
            for x in query]


def get_routers_by_flavor(session, flavor, router_ids=None):
    """Retrieve a list of router IDs with the given flavor."""
    query = session.query(RouterProvider.router_id)
    query = _get_router_flavors_query(query, flavor, router_ids)
    return [x[0] for x in query]


def get_router_count_by_flavor(session, flavor, tenant_id=None):
    query = session.query(RouterProvider).filter_by(flavor=flavor)
    if tenant_id:
        query = (query.join('router').
                 filter(l3_db.Router.tenant_id == tenant_id))
    return query.count()


def get_flavor_by_router(session, router_id):
    """Retrieve a flavor of the given router."""
    try:
        binding = (session.query(RouterProvider).
                   filter_by(router_id=router_id).
                   one())
    except sa_exc.NoResultFound:
        return None
    return binding.flavor


def add_router_flavor_binding(session, flavor, router_id):
    LOG.debug(_("Add flavor binding (router=%(router_id)s, flavor=%(flavor)s"),
              {'router_id': router_id, 'flavor': flavor})
    binding = RouterProvider(flavor=flavor, router_id=router_id)
    session.add(binding)
    return binding
