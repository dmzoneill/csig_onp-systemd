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

#include <ctype.h>
#include <net/if.h>
#include <net/ethernet.h>

#include "networkd.h"
#include "networkd-netdev.h"
#include "networkd-link.h"
#include "network-internal.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "util.h"

/* create a new FDB entry or get an existing one. */
int fdb_entry_new_static(Network *const network,
                         const unsigned section,
                         FdbEntry **ret) {
        _cleanup_fdbentry_free_ FdbEntry *fdb_entry = NULL;
        struct ether_addr *mac_addr = NULL;

        assert(network);

        /* search entry in hashmap first. */
        if(section) {
                fdb_entry = hashmap_get(network->fdb_entries_by_section, UINT_TO_PTR(section));
                if (fdb_entry) {
                        *ret = fdb_entry;
                        fdb_entry = NULL;

                        return 0;
                }
        }

        /* allocate space for MAC address. */
        mac_addr = new0(struct ether_addr, 1);
        if (!mac_addr)
                return -ENOMEM;

        /* allocate space for a new FDB entry. */
        fdb_entry = new0(FdbEntry, 1);

        if (!fdb_entry) {
                /* free previously allocated space for mac_addr. */
                free(mac_addr);
                return -ENOMEM;
        }

        /* init FDB structure. */
        fdb_entry->network = network;
        fdb_entry->mac_addr = mac_addr;

        LIST_PREPEND(static_fdb_entries, network->static_fdb_entries, fdb_entry);

        if (section) {
                fdb_entry->section = section;
                hashmap_put(network->fdb_entries_by_section,
                            UINT_TO_PTR(fdb_entry->section), fdb_entry);
        }

        /* return allocated FDB structure. */
        *ret = fdb_entry;
        fdb_entry = NULL;

        return 0;
}

static int fdb_delete_existing(sd_rtnl *const rtnl,
                               sd_rtnl_message *const fdb,
                               const int ifindex) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *del_req = NULL;
        bool got_vlan_info = false; /* suppose we don't have VLAN info by default. */
        struct ether_addr mac;
        uint16_t vlan = 0;
        uint8_t flags;
        uint16_t state;
        int r;

        r = sd_rtnl_message_read_ether_addr(fdb, NDA_LLADDR, &mac);
        if (r < 0)
                return rtnl_log_parse_error(r);

        /* check if we have VLAN info available. */
        r = sd_rtnl_message_read_u16(fdb, NDA_VLAN, &vlan);
        if (r >= 0)
                got_vlan_info = true;

        r = sd_rtnl_message_neigh_get_flags(fdb, &flags);
        if (r < 0)
                return rtnl_log_parse_error(r);

        r = sd_rtnl_message_neigh_get_state(fdb, &state);
        if(r < 0)
                return rtnl_log_parse_error(r);

        /* delete current entry. */
        r = sd_rtnl_message_new_neigh(rtnl, &del_req, RTM_DELNEIGH, ifindex, PF_BRIDGE);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_append_ether_addr(del_req, NDA_LLADDR, &mac);
        if (r < 0)
                return rtnl_log_create_error(r);

        if (false != got_vlan_info) {
                r = sd_rtnl_message_append_u16(del_req, NDA_VLAN, vlan);
                if (r < 0)
                        return rtnl_log_create_error(r);
        }

        r = sd_rtnl_message_neigh_set_flags(del_req, flags);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_neigh_set_state(del_req, state);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* send delete request to kernel. */
        r = sd_rtnl_call(rtnl, del_req, 0, NULL);
        if (r < 0)
                return r;

        return 0;
}


/* clear FDB entries for current port. */
int fdb_entries_clear(sd_rtnl *const rtnl,
                      const int ifindex) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL, *fdb = NULL;
        int r;

        assert(rtnl);

        /* create new RTM message for getting the FDB table for this port. */
        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_GETNEIGH, ifindex, PF_BRIDGE);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* send GET request to the kernel. */
        r = sd_rtnl_call(rtnl, req, 0, &reply);
        if (r < 0) {
                log_error("Could not send or get rtnetlink message: %s", strerror(-r));
                return r;
        }

        /* look through the returned table and find the entries that match this interface name. */
        for(fdb = reply; fdb; fdb = sd_rtnl_message_next(fdb)) {
                int fdb_ifindex;

                /* get ifindex for current entry. */
                r = sd_rtnl_message_neigh_get_ifindex(fdb, &fdb_ifindex);
                if (r < 0)
                        return rtnl_log_parse_error(r);

                /* check if the entry is for current interface. If yes, delete it. */
                if (fdb_ifindex == ifindex) {
                        r = fdb_delete_existing(rtnl, fdb, ifindex);

                        /* between getting & deleting an entry,
                         * the kernel may delete it due to some other events
                         * like stopping networkd. Do not return error for ENOENT */
                        if (r < 0 && r != -ENOENT)
                                return r;
                }
        }

        /* the FDB entries were succesfully configured for this port. */
        return 0;
}

static int set_fdb_handler(sd_rtnl *rtnl, sd_rtnl_message *m, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        r = sd_rtnl_message_get_errno(m);
        if (r < 0 && r != -EEXIST)
                log_error("%s: Could not add FDB entry: %s", link->ifname, strerror(-r));

        return 1;
}

/* send a request to the kernel to add a FDB entry in its static MAC table. */
int fdb_entry_configure(Link *const link, FdbEntry *const fdb_entry) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        sd_rtnl *rtnl;
        int r;

        assert(link);
        assert(link->manager);
        assert(fdb_entry);

        rtnl = link->manager->rtnl;

        /* create new RTM message */
        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_NEWNEIGH, link->ifindex, PF_BRIDGE);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* only NTF_SELF flag supported. */
        r = sd_rtnl_message_neigh_set_flags(req, NTF_SELF);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* only NUD_PERMANENT state supported. */
        r = sd_rtnl_message_neigh_set_state(req, NUD_NOARP | NUD_PERMANENT);
        if (r < 0)
                return rtnl_log_create_error(r);

        r = sd_rtnl_message_append_ether_addr(req, NDA_LLADDR, fdb_entry->mac_addr);
        if (r < 0)
                return rtnl_log_create_error(r);

        /* VLAN Id is optional. We'll add VLAN Id only if it's specified. */
        if (0 != fdb_entry->vlan_id) {
                r = sd_rtnl_message_append_u16(req, NDA_VLAN, fdb_entry->vlan_id);
                if (r < 0)
                        return rtnl_log_create_error(r);
        }

        /* send message to the kernel to update its internal static MAC table. */
        r = sd_rtnl_call_async(rtnl, req, set_fdb_handler, link, 0, NULL);
        if (r < 0) {
                log_error("Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

/* remove and FDB entry. */
void fdb_entry_free(FdbEntry *fdb_entry) {
        if(!fdb_entry)
                return;

        if(fdb_entry->network) {
                LIST_REMOVE(static_fdb_entries, fdb_entry->network->static_fdb_entries,
                            fdb_entry);

                if(fdb_entry->section)
                    hashmap_remove(fdb_entry->network->fdb_entries_by_section,
                                   UINT_TO_PTR(fdb_entry->section));
        }

        free(fdb_entry->mac_addr);

        free(fdb_entry);
}

/* parse the HW address from config files. */
int config_parse_fdb_hwaddr(const char *unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {
        Network *network = userdata;
        _cleanup_fdbentry_free_ FdbEntry *fdb_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, section_line, &fdb_entry);
        if (r < 0) {
                log_error("Failed to allocate a new FDB entry: %s", strerror(-r));
                return r;
        }

        /* read in the MAC address for the FDB table. */
        r = sscanf(rvalue, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                   &fdb_entry->mac_addr->ether_addr_octet[0],
                   &fdb_entry->mac_addr->ether_addr_octet[1],
                   &fdb_entry->mac_addr->ether_addr_octet[2],
                   &fdb_entry->mac_addr->ether_addr_octet[3],
                   &fdb_entry->mac_addr->ether_addr_octet[4],
                   &fdb_entry->mac_addr->ether_addr_octet[5]);

        if (ETHER_ADDR_LEN !=  r) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Not a valid MAC address, ignoring assignment: %s", rvalue);
                return 0;
        }

        fdb_entry = NULL;

        return 0;
}

/* parse the VLAN Id from config files. */
int config_parse_fdb_vlan_id(const char *unit,
                             const char *filename,
                             unsigned line,
                             const char *section,
                             unsigned section_line,
                             const char *lvalue,
                             int ltype,
                             const char *rvalue,
                             void *data,
                             void *userdata) {
        Network *network = userdata;
        _cleanup_fdbentry_free_ FdbEntry *fdb_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = fdb_entry_new_static(network, section_line, &fdb_entry);
        if (r < 0) {
                log_error("Failed to allocate a new FDB entry: %s", strerror(-r));
                return r;
        }

        r = config_parse_unsigned(unit, filename, line, section,
                                  section_line, lvalue, ltype,
                                  rvalue, &fdb_entry->vlan_id, userdata);
        if (r < 0) {
                log_error("Failed to parse the unsigned integer: %s", strerror(-r));
                return r;
        }

        fdb_entry = NULL;

        return 0;
}
