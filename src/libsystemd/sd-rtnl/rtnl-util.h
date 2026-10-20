/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (C) 2013 Tom Gundersen <teg@jklm.no>
 */

#include <netinet/ether.h>

#include "shared/util.h"
#include "systemd/sd-rtnl.h"

int rtnl_message_new_synthetic_error(int error, uint32_t serial,
                                     sd_rtnl_message **ret);
uint32_t rtnl_message_get_serial(sd_rtnl_message *m);
void rtnl_message_seal(sd_rtnl_message *m);

bool rtnl_message_type_is_link(uint16_t type);
bool rtnl_message_type_is_addr(uint16_t type);
bool rtnl_message_type_is_route(uint16_t type);
bool rtnl_message_type_is_neigh(uint16_t type);

int rtnl_set_link_name(sd_rtnl **rtnl, int ifindex, const char *name);
int rtnl_set_link_properties(sd_rtnl **rtnl, int ifindex, const char *alias,
                             const struct ether_addr *mac, unsigned mtu);

int rtnl_log_parse_error(int r);
int rtnl_log_create_error(int r);

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_rtnl *, sd_rtnl_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(sd_rtnl_message *, sd_rtnl_message_unref);

#define _cleanup_rtnl_unref_ _cleanup_(sd_rtnl_unrefp)
#define _cleanup_rtnl_message_unref_ _cleanup_(sd_rtnl_message_unrefp)
