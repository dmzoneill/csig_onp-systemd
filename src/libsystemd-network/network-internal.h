/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (C) 2013 Tom Gundersen <teg@jklm.no>
 */

#include <netinet/ether.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>

#include "shared/condition-util.h"
#include "udev/udev.h"

bool net_match_config(const struct ether_addr *match_mac,
                      const char *match_path, const char *match_driver,
                      const char *match_type, const char *match_name,
                      Condition *match_host, Condition *match_virt,
                      Condition *match_kernel, Condition *match_arch,
                      const unsigned int *match_phys_port_id,
                      const struct ether_addr *dev_mac, const char *dev_path,
                      const char *dev_parent_driver, const char *dev_driver,
                      const char *dev_type, const char *dev_name,
                      const unsigned int *phys_port_id);

int config_parse_net_condition(const char *unit, const char *filename,
                               unsigned line, const char *section,
                               unsigned section_line, const char *lvalue,
                               int ltype, const char *rvalue, void *data,
                               void *userdata);

int config_parse_hwaddr(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line,
                        const char *lvalue, int ltype, const char *rvalue,
                        void *data, void *userdata);

int config_parse_ifname(const char *unit, const char *filename, unsigned line,
                        const char *section, unsigned section_line,
                        const char *lvalue, int ltype, const char *rvalue,
                        void *data, void *userdata);

int config_parse_ifalias(const char *unit, const char *filename, unsigned line,
                         const char *section, unsigned section_line,
                         const char *lvalue, int ltype, const char *rvalue,
                         void *data, void *userdata);

int net_get_unique_predictable_data(struct udev_device *device,
                                    uint8_t result[8]);
const char *net_get_name(struct udev_device *device);

void serialize_in_addrs(FILE *f, const struct in_addr *addresses, size_t size);
int deserialize_in_addrs(struct in_addr **addresses, const char *text);
int deserialize_in6_addrs(struct in6_addr **addresses, const char *text);

/* don't include "dhcp-lease-internal.h" as it causes conflicts between
 * netinet/ip.h and linux/ip.h */
struct sd_dhcp_route;

void serialize_dhcp_routes(FILE *f, const char *key,
                           struct sd_dhcp_route *routes, size_t size);
int deserialize_dhcp_routes(struct sd_dhcp_route **ret, size_t *ret_size,
                            size_t *ret_allocated, const char *text);
