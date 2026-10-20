/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (C) 2013 Tom Gundersen <teg@jklm.no>
 */

#pragma once

#include "udev/net/ethtool-util.h"

#include "libudev/libudev.h"
#include "shared/condition-util.h"
#include "shared/list.h"
#include "shared/util.h"

typedef struct link_config_ctx link_config_ctx;
typedef struct link_config link_config;

typedef enum MACPolicy {
  MACPOLICY_PERSISTENT,
  MACPOLICY_RANDOM,
  _MACPOLICY_MAX,
  _MACPOLICY_INVALID = -1
} MACPolicy;

typedef enum NamePolicy {
  NAMEPOLICY_KERNEL,
  NAMEPOLICY_DATABASE,
  NAMEPOLICY_ONBOARD,
  NAMEPOLICY_SLOT,
  NAMEPOLICY_PATH,
  NAMEPOLICY_MAC,
  _NAMEPOLICY_MAX,
  _NAMEPOLICY_INVALID = -1
} NamePolicy;

struct link_config {
  char *filename;

  struct ether_addr *match_mac;
  char *match_path;
  char *match_driver;
  char *match_type;
  Condition *match_host;
  Condition *match_virt;
  Condition *match_kernel;
  Condition *match_arch;
  unsigned int match_phys_port_id;

  char *description;
  struct ether_addr *mac;
  MACPolicy mac_policy;
  NamePolicy *name_policy;
  char *name;
  char *alias;
  size_t mtu;
  unsigned int speed;
  Duplex duplex;
  WakeOnLan wol;

  LIST_FIELDS(link_config, links);
};

int link_config_ctx_new(link_config_ctx **ret);
void link_config_ctx_free(link_config_ctx *ctx);

int link_config_load(link_config_ctx *ctx);
bool link_config_should_reload(link_config_ctx *ctx);

int link_config_get(link_config_ctx *ctx, struct udev_device *device,
                    struct link_config **ret);
int link_config_apply(link_config_ctx *ctx, struct link_config *config,
                      struct udev_device *device, const char **name);

int link_get_driver(link_config_ctx *ctx, struct udev_device *device,
                    char **ret);

const char *name_policy_to_string(NamePolicy p) _const_;
NamePolicy name_policy_from_string(const char *p) _pure_;

const char *mac_policy_to_string(MACPolicy p) _const_;
MACPolicy mac_policy_from_string(const char *p) _pure_;

/* gperf lookup function */
const struct ConfigPerfItem *link_config_gperf_lookup(const char *key,
                                                      unsigned length);

int config_parse_mac_policy(const char *unit, const char *filename,
                            unsigned line, const char *section,
                            unsigned section_line, const char *lvalue,
                            int ltype, const char *rvalue, void *data,
                            void *userdata);
int config_parse_name_policy(const char *unit, const char *filename,
                             unsigned line, const char *section,
                             unsigned section_line, const char *lvalue,
                             int ltype, const char *rvalue, void *data,
                             void *userdata);
