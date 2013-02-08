# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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

import sqlalchemy as sa

from quantum.db import api as db
from quantum.db import model_base
from quantum.openstack.common import log as logging
# NOTE (e0ne): this import is needed for config init
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import models as nmodels


LOG = logging.getLogger(__name__)
OFP_VLAN_NONE = 0xffff


def initialize():
    db.configure_db()


def clear_db(base=model_base.BASEV2):
    db.clear_db(base)


def get_ofc_item(model, id):
    session = db.get_session()
    try:
        return (session.query(model).
                filter_by(id=id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def find_ofc_item(model, ofc_id):
    session = db.get_session()
    try:
        return (session.query(model).
                filter_by(ofc_id=ofc_id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def add_ofc_item(model, id, ofc_id):
    session = db.get_session()
    try:
        item = model(id=id, ofc_id=ofc_id)
        session.add(item)
        session.flush()
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException
    return item


def del_ofc_item(model, id):
    session = db.get_session()
    try:
        item = (session.query(model).
                filter_by(id=id).
                one())
        session.delete(item)
        session.flush()
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("_del_ofc_item(): NotFound item "
                      "(model=%(model)s, id=%(id)s) "),
                    {'model': model, 'id': id})


def get_portinfo(id):
    session = db.get_session()
    try:
        return (session.query(nmodels.PortInfo).
                filter_by(id=id).
                one())
    except sa.orm.exc.NoResultFound:
        return None


def add_portinfo(id, datapath_id='', port_no=0, vlan_id=OFP_VLAN_NONE, mac=''):
    session = db.get_session()
    try:
        portinfo = nmodels.PortInfo(id=id, datapath_id=datapath_id,
                                    port_no=port_no, vlan_id=vlan_id, mac=mac)
        session.add(portinfo)
        session.flush()
    except Exception as exc:
        LOG.exception(exc)
        raise nexc.NECDBException
    return portinfo


def del_portinfo(id):
    session = db.get_session()
    try:
        portinfo = (session.query(nmodels.PortInfo).
                    filter_by(id=id).
                    one())
        session.delete(portinfo)
        session.flush()
    except sa.orm.exc.NoResultFound:
        LOG.warning(_("del_portinfo(): NotFound portinfo for "
                      "port_id: %s"), id)
