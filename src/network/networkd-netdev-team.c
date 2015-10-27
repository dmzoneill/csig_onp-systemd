/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_team.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <net/if.h>

#include "conf-parser.h"
#include "sd-rtnl.h"
#include "rtnl-util.h"
#include "rtnl-types.h"
#include "networkd-netdev-team.h"

static int netdev_team_dump_all_interfaces(sd_rtnl *rtnl, sd_rtnl_message **ret) {
        int r;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;

        assert(rtnl);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_GETLINK, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_call(rtnl, req, 0, ret);
        if (r < 0) {
                log_error("Could not send request: %s", strerror(-r));
                return r;
        }

        return 0;
}

static int netdev_team_delete_interface(sd_rtnl *rtnl, const sd_rtnl_message *msg, int ifindex) {
        int r;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;

        assert(rtnl);
        assert(msg);

        r = sd_rtnl_message_new_link(rtnl, &req, RTM_DELLINK, ifindex);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_call(rtnl, req, 0, NULL);
        if (r < 0) {
                log_error("Could not send request: %s", strerror(-r));
                return r;
        }

        return 0;
}

int netdev_team_delete_not_configured(Manager *manager) {
        int r, ifindex;
        NetDev *netdev = NULL;
        const char *kind = NULL;
        char ifname[IFNAMSIZ];
        _cleanup_rtnl_message_unref_ sd_rtnl_message *ifaces = NULL, *iface = NULL;

        assert(manager);
        assert(manager->rtnl);

        r = netdev_team_dump_all_interfaces(manager->rtnl, &ifaces);
        if (r < 0) {
                log_error("Failed to dump interfaces: %s", strerror(-r));
                return r;
        }

       for(iface = ifaces; iface; iface = sd_rtnl_message_next(iface)) {
               r = sd_rtnl_message_get_errno(iface);
               if (r < 0)
                       return r;

               r = sd_rtnl_message_link_get_ifindex(iface, &ifindex);
               if (r < 0)
                       return rtnl_log_parse_error(r);

               /* skip message if it doesn't contain link info */
               r = sd_rtnl_message_enter_container(iface, IFLA_LINKINFO);
               if (r < 0)
                       continue;

               r = sd_rtnl_message_read_string(iface, IFLA_INFO_KIND, &kind);
               if (r == 0) {
                       if (NL_UNION_LINK_INFO_DATA_TEAM != nl_union_link_info_data_from_string(kind))
                               continue;

                       if (if_indextoname(ifindex, ifname) == NULL)
                               return errno;

                       r = netdev_get(manager, ifname, &netdev);
                       if (r == 0) /* netdev exists */
                               continue;

                       if (r != -ENOENT)
                               return r;

                       r = netdev_team_delete_interface(manager->rtnl, iface, ifindex);
                       if (r < 0)
                               return r;
               }

               r = sd_rtnl_message_exit_container(iface);
               if (r < 0)
                       return rtnl_log_parse_error(r);
       }

       return 0;
}

static bool netdev_team_is_master(NetDev *netdev, sd_rtnl_message *iface) {
        int r, master;
        char master_name[IFNAMSIZ];

        r = sd_rtnl_message_read_u32(iface, IFLA_MASTER, (unsigned *)&master);
        if (r < 0)
                return false; /* interface is not enslaved */

        if (if_indextoname(master, master_name) == NULL)
                return false;

        return streq(master_name, netdev->ifname);
}

static int netdev_team_remove_master(NetDev *netdev, int ifindex) {
        int r;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;

        assert(netdev);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &req, RTM_SETLINK, ifindex);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_append_u32(req, IFLA_MASTER, 0);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_call(netdev->manager->rtnl, req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}

static int netdev_team_remove_slaves(NetDev *netdev) {
        int r, ifindex;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *ifaces = NULL, *iface = NULL;

        assert(netdev);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);

        r = netdev_team_dump_all_interfaces(netdev->manager->rtnl, &ifaces);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Failed to dump interfaces: %s",
                                 strerror(-r));
                return r;
        }

        for (iface = ifaces; iface; iface = sd_rtnl_message_next(iface)) {
                r = sd_rtnl_message_get_errno(iface);
                if (r < 0)
                        return r;

                if (!netdev_team_is_master(netdev, iface))
                        continue;

                r = sd_rtnl_message_link_get_ifindex(iface, &ifindex);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                r = netdev_team_remove_master(netdev, ifindex);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not remove master from %d interface: %s",
                                         ifindex, strerror(-r));
                }
        }

        return 0;
}

static void netdev_team_init(NetDev *netdev) {
        Team *team = TEAM(netdev);

        assert(team);
}

static void netdev_team_done(NetDev *netdev) {
        Team *team = TEAM(netdev);

        assert(team);
}

static int netdev_team_create(NetDev *netdev) {
        int r;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *m = NULL, *reply = NULL;
        Team *team = TEAM(netdev);

        assert(netdev);
        assert(netdev->manager);
        assert(netdev->manager->rtnl);
        assert(team);

        r = sd_rtnl_message_new_link(netdev->manager->rtnl, &m, RTM_NEWLINK, 0);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not allocate RTM_NEWLINK message: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_string(m, IFLA_IFNAME, netdev->ifname);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_IFNAME, attribute: %s",
                                 strerror(-r));
                return r;
        }

        if (netdev->mac) {
                r = sd_rtnl_message_append_ether_addr(m, IFLA_ADDRESS, netdev->mac);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_ADDRESS attribute: %s",
                                         strerror(-r));
                    return r;
                }
        }

        if (netdev->mtu) {
                r = sd_rtnl_message_append_u32(m, IFLA_MTU, netdev->mtu);
                if (r < 0) {
                        log_error_netdev(netdev,
                                         "Could not append IFLA_MTU attribute: %s",
                                         strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_message_open_container(m, IFLA_LINKINFO);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container_union(m, IFLA_INFO_DATA,
                                                 netdev_kind_to_string(netdev->kind));
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_INFO_DATA attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(m);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not append IFLA_LINKINFO attribute: %s",
                                 strerror(-r));
                return r;
        }

        r = sd_rtnl_call(netdev->manager->rtnl, m, 0, &reply);
        if (r < 0 && r != -EEXIST) {
                log_error_netdev(netdev,
                                 "Could not send rtnetlink message: %s",
                                 strerror(-r));
                return r;
        }

        r = netdev_team_remove_slaves(netdev);
        if (r < 0) {
                log_error_netdev(netdev,
                                 "Could not remove slave devices: %s",
                                 strerror(-r));
                return r;
        }

        netdev->state = NETDEV_STATE_CREATING;

        return 0;
}

const NetDevVTable team_vtable = {
        .object_size = sizeof(Team),
        .init = netdev_team_init,
        .done = netdev_team_done,
        .sections = "Match\0NetDev\0Team\0",
        .create_type = NETDEV_CREATE_MASTER,
        .create = netdev_team_create,
};
