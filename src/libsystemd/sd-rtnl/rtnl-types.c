/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>

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

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/in6.h>
#include <linux/veth.h>
#include <linux/if_bridge.h>
#include <linux/if_addr.h>
#include <linux/if.h>

#include <linux/ip.h>
#include <linux/if_tunnel.h>

#include "macro.h"
#include "util.h"

#include "rtnl-types.h"
#include "missing.h"

static const NLTypeSystem rtnl_link_type_system;

static const NLType rtnl_link_info_data_veth_types[VETH_INFO_MAX + 1] = {
        [VETH_INFO_PEER]  = { .type = NLA_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
};


static const NLType rtnl_link_info_data_macvlan_types[IFLA_MACVLAN_MAX + 1] = {
        [IFLA_MACVLAN_MODE]  = { .type = NLA_U32 },
        [IFLA_MACVLAN_FLAGS] = { .type = NLA_U16 },
};

static const NLType rtnl_link_info_data_bridge_types[IFLA_BRIDGE_MAX + 1] = {
        [IFLA_BRIDGE_FLAGS]     = { .type = NLA_U16 },
        [IFLA_BRIDGE_MODE]      = { .type = NLA_U16 },

        [IFLA_BRIDGE_VLAN_INFO] = { .type = NLA_BINARY,
                                    .size = sizeof(struct bridge_vlan_info), },

};

static const NLType rtnl_link_info_data_vlan_types[IFLA_VLAN_MAX + 1] = {
        [IFLA_VLAN_ID]          = { .type = NLA_U16 },
/*
        [IFLA_VLAN_FLAGS]       = { .len = sizeof(struct ifla_vlan_flags) },
        [IFLA_VLAN_EGRESS_QOS]  = { .type = NLA_NESTED },
        [IFLA_VLAN_INGRESS_QOS] = { .type = NLA_NESTED },
*/
        [IFLA_VLAN_PROTOCOL]    = { .type = NLA_U16 },
};

static const NLType rtnl_link_info_data_vxlan_types[IFLA_VXLAN_MAX+1] = {
        [IFLA_VXLAN_ID] = { .type = NLA_U32 },
        [IFLA_VXLAN_GROUP] = {.type = NLA_IN_ADDR },
        [IFLA_VXLAN_LINK] = { .type = NLA_U32 },
        [IFLA_VXLAN_LOCAL] = { .type = NLA_U32 },
        [IFLA_VXLAN_TTL] = { .type = NLA_U8 },
        [IFLA_VXLAN_TOS] = { .type = NLA_U8 },
        [IFLA_VXLAN_LEARNING] = { .type = NLA_U8 },
        [IFLA_VXLAN_AGEING] = { .type = NLA_U32 },
        [IFLA_VXLAN_LIMIT] = { .type = NLA_U32 },
        [IFLA_VXLAN_PORT_RANGE] = { .type = NLA_U32 },
        [IFLA_VXLAN_PROXY] = { .type = NLA_U8 },
        [IFLA_VXLAN_RSC] = { .type = NLA_U8 },
        [IFLA_VXLAN_L2MISS] = { .type = NLA_U8 },
        [IFLA_VXLAN_L3MISS] = { .type = NLA_U8 },
};

static const NLType rtnl_link_info_data_bond_types[IFLA_BOND_MAX + 1] = {
        [IFLA_BOND_MODE]                = { .type = NLA_U8 },
        [IFLA_BOND_ACTIVE_SLAVE]        = { .type = NLA_U32 },
        [IFLA_BOND_MIIMON]              = { .type = NLA_U32 },
        [IFLA_BOND_UPDELAY]             = { .type = NLA_U32 },
        [IFLA_BOND_DOWNDELAY]           = { .type = NLA_U32 },
        [IFLA_BOND_USE_CARRIER]         = { .type = NLA_U8 },
        [IFLA_BOND_ARP_INTERVAL]        = { .type = NLA_U32 },
        [IFLA_BOND_ARP_IP_TARGET]       = { .type = NLA_NESTED },
        [IFLA_BOND_ARP_VALIDATE]        = { .type = NLA_U32 },
        [IFLA_BOND_ARP_ALL_TARGETS]     = { .type = NLA_U32 },
        [IFLA_BOND_PRIMARY]             = { .type = NLA_U32 },
        [IFLA_BOND_PRIMARY_RESELECT]    = { .type = NLA_U8 },
        [IFLA_BOND_FAIL_OVER_MAC]       = { .type = NLA_U8 },
        [IFLA_BOND_XMIT_HASH_POLICY]    = { .type = NLA_U8 },
        [IFLA_BOND_RESEND_IGMP]         = { .type = NLA_U32 },
        [IFLA_BOND_NUM_PEER_NOTIF]      = { .type = NLA_U8 },
        [IFLA_BOND_ALL_SLAVES_ACTIVE]   = { .type = NLA_U8 },
        [IFLA_BOND_MIN_LINKS]           = { .type = NLA_U32 },
        [IFLA_BOND_LP_INTERVAL]         = { .type = NLA_U32 },
        [IFLA_BOND_PACKETS_PER_SLAVE]   = { .type = NLA_U32 },
        [IFLA_BOND_AD_LACP_RATE]        = { .type = NLA_U8 },
        [IFLA_BOND_AD_SELECT]           = { .type = NLA_U8 },
        [IFLA_BOND_AD_INFO]             = { .type = NLA_NESTED },
};

static const NLType rtnl_link_info_data_iptun_types[IFLA_IPTUN_MAX + 1] = {
        [IFLA_IPTUN_LINK]                = { .type = NLA_U32 },
        [IFLA_IPTUN_LOCAL]               = { .type = NLA_IN_ADDR },
        [IFLA_IPTUN_REMOTE]              = { .type = NLA_IN_ADDR },
        [IFLA_IPTUN_TTL]                 = { .type = NLA_U8 },
        [IFLA_IPTUN_TOS]                 = { .type = NLA_U8 },
        [IFLA_IPTUN_PMTUDISC]            = { .type = NLA_U8 },
        [IFLA_IPTUN_FLAGS]               = { .type = NLA_U16 },
        [IFLA_IPTUN_PROTO]               = { .type = NLA_U8 },
        [IFLA_IPTUN_6RD_PREFIX]          = { .type = NLA_IN_ADDR },
        [IFLA_IPTUN_6RD_RELAY_PREFIX]    = { .type = NLA_U32 },
        [IFLA_IPTUN_6RD_PREFIXLEN]       = { .type = NLA_U16 },
        [IFLA_IPTUN_6RD_RELAY_PREFIXLEN] = { .type = NLA_U16 },
};

static  const NLType rtnl_link_info_data_ipgre_types[IFLA_GRE_MAX + 1] = {
        [IFLA_GRE_LINK]     = { .type = NLA_U32 },
        [IFLA_GRE_IFLAGS]   = { .type = NLA_U16 },
        [IFLA_GRE_OFLAGS]   = { .type = NLA_U16 },
        [IFLA_GRE_IKEY]     = { .type = NLA_U32 },
        [IFLA_GRE_OKEY]     = { .type = NLA_U32 },
        [IFLA_GRE_LOCAL]    = { .type = NLA_IN_ADDR },
        [IFLA_GRE_REMOTE]   = { .type = NLA_IN_ADDR },
        [IFLA_GRE_TTL]      = { .type = NLA_U8 },
        [IFLA_GRE_TOS]      = { .type = NLA_U8 },
        [IFLA_GRE_PMTUDISC] = { .type = NLA_U8 },
};

static const NLType rtnl_link_info_data_ipvti_types[IFLA_VTI_MAX + 1] = {
        [IFLA_VTI_LINK]         = { .type = NLA_U32 },
        [IFLA_VTI_IKEY]         = { .type = NLA_U32 },
        [IFLA_VTI_OKEY]         = { .type = NLA_U32 },
        [IFLA_VTI_LOCAL]        = { .type = NLA_IN_ADDR  },
        [IFLA_VTI_REMOTE]       = { .type = NLA_IN_ADDR  },
};

/* these strings must match the .kind entries in the kernel */
static const char* const nl_union_link_info_data_table[_NL_UNION_LINK_INFO_DATA_MAX] = {
        [NL_UNION_LINK_INFO_DATA_BOND] = "bond",
        [NL_UNION_LINK_INFO_DATA_BRIDGE] = "bridge",
        [NL_UNION_LINK_INFO_DATA_VLAN] = "vlan",
        [NL_UNION_LINK_INFO_DATA_VETH] = "veth",
        [NL_UNION_LINK_INFO_DATA_DUMMY] = "dummy",
        [NL_UNION_LINK_INFO_DATA_MACVLAN] = "macvlan",
        [NL_UNION_LINK_INFO_DATA_VXLAN] = "vxlan",
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] = "ipip",
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] = "gre",
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] = "sit",
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] = "vti",
        [NL_UNION_LINK_INFO_DATA_TEAM] = "team",
};

DEFINE_STRING_TABLE_LOOKUP(nl_union_link_info_data, NLUnionLinkInfoData);

static const NLTypeSystem rtnl_link_info_data_type_systems[_NL_UNION_LINK_INFO_DATA_MAX] = {
        [NL_UNION_LINK_INFO_DATA_BOND] =        { .max = ELEMENTSOF(rtnl_link_info_data_bond_types) - 1,
                                                  .types = rtnl_link_info_data_bond_types },
        [NL_UNION_LINK_INFO_DATA_BRIDGE] =      { .max = ELEMENTSOF(rtnl_link_info_data_bridge_types) - 1,
                                                  .types = rtnl_link_info_data_bridge_types },
        [NL_UNION_LINK_INFO_DATA_VLAN] =        { .max = ELEMENTSOF(rtnl_link_info_data_vlan_types) - 1,
                                                  .types = rtnl_link_info_data_vlan_types },
        [NL_UNION_LINK_INFO_DATA_VETH] =        { .max = ELEMENTSOF(rtnl_link_info_data_veth_types) - 1,
                                                  .types = rtnl_link_info_data_veth_types },
        [NL_UNION_LINK_INFO_DATA_MACVLAN] =     { .max = ELEMENTSOF(rtnl_link_info_data_macvlan_types) - 1,
                                                  .types = rtnl_link_info_data_macvlan_types },
        [NL_UNION_LINK_INFO_DATA_VXLAN] =       { .max = ELEMENTSOF(rtnl_link_info_data_vxlan_types) - 1,
                                                  .types = rtnl_link_info_data_vxlan_types },
        [NL_UNION_LINK_INFO_DATA_IPIP_TUNNEL] = { .max = ELEMENTSOF(rtnl_link_info_data_iptun_types) - 1,
                                                  .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_IPGRE_TUNNEL] =  { .max = ELEMENTSOF(rtnl_link_info_data_ipgre_types) - 1,
                                                    .types = rtnl_link_info_data_ipgre_types },
        [NL_UNION_LINK_INFO_DATA_SIT_TUNNEL] =  { .max = ELEMENTSOF(rtnl_link_info_data_iptun_types) - 1,
                                                  .types = rtnl_link_info_data_iptun_types },
        [NL_UNION_LINK_INFO_DATA_VTI_TUNNEL] =  { .max = ELEMENTSOF(rtnl_link_info_data_ipvti_types) - 1,
                                                  .types = rtnl_link_info_data_ipvti_types },
};

static const NLTypeSystemUnion rtnl_link_info_data_type_system_union = {
        .num = _NL_UNION_LINK_INFO_DATA_MAX,
        .lookup = nl_union_link_info_data_from_string,
        .type_systems = rtnl_link_info_data_type_systems,
        .match = IFLA_INFO_KIND,
};

static const NLType rtnl_link_info_types[IFLA_INFO_MAX + 1] = {
        [IFLA_INFO_KIND]        = { .type = NLA_STRING },
        [IFLA_INFO_DATA]        = { .type = NLA_UNION, .type_system_union = &rtnl_link_info_data_type_system_union},
/*
        [IFLA_INFO_XSTATS],
        [IFLA_INFO_SLAVE_KIND]  = { .type = NLA_STRING },
        [IFLA_INFO_SLAVE_DATA]  = { .type = NLA_NESTED },
*/
};

static const NLTypeSystem rtnl_link_info_type_system = {
        .max = ELEMENTSOF(rtnl_link_info_types) - 1,
        .types = rtnl_link_info_types,
};
static const NLType rtnl_swport_types[IFLA_ATTR_MAX + 1] = {
        [IFLA_ATTR_DEF_CFI] =                             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_DSCP] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_PRI] =                             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_SWPRI] =                           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_VLAN] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DROP_BV] =                             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DROP_TAGGED] =                         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DROP_UNTAGGED] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EEE_MODE] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EEE_TX_ACTIVITY_TIMEOUT] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EEE_TX_LPI_TIMEOUT] =                  { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_FABRIC_LOOPBACK] =                     { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_IGNORE_IFG_ERRORS] =                   { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LEARNING] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LOOPBACK] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PARSE_MPLS] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PARSER] =                              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PARSER_STORE_MPLS] =                   { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PARSER_VLAN1_TAG] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TAGGING] =                             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TIMESTAMP_GENERATION] =                { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_UPDATE_DSCP] =                         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_UPDATE_TTL] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_AUTONEG] =                             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_AUTONEG_BASEPAGE] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_AUTONEG_LINK_INHB_TIMER] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_AUTONEG_LINK_INHB_TIMER_KX] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_REPLACE_DSCP] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_ROUTED_FRAME_UPDATE_FIELDS] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_RX_CLASS_PAUSE] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_RX_CUT_THROUGH] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SWPRI_DSCP_PREF] =                     { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SWPRI_SOURCE] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TX_CUT_THROUGH] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PAUSE_MODE] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_PRI2] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEF_VLAN2] =                           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DOT1X_STATE] =                         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_PARSER_VLAN2_TAG] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SECURITY_ACTION] =                     { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TAGGING2] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_BCAST_FLOODING] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_UCAST_FLOODING] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MCAST_FLOODING] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LOW_EYE_SCORE_TIMEOUT] =               { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LOW_EYE_SCORE_THRESHOLD] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LOW_EYE_SCORE_RECOVERY] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MCAST_PRUNING] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_BCAST_PRUNING] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_UCAST_PRUNING] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MAC_TABLE_ADDRESS_AGING_TIME] =        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MAX_FRAME_SIZE] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_AUTO_PAUSE_MODE] =                     { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_DSCP_SWPRI_MAP] =                  { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_GLOBAL_USAGE] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_PRIV_WM] =                         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_PRI_WM] =                   { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_SOFT_DROP_WM] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_SOFT_DROP_WM_HOG] =         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SHARED_SOFT_DROP_WM_JITTER] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_USAGE] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SWPRI_TC_MAP] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_TC_SMP_MAP] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_TRAP_CLASS_SWPRI_MAP] =            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_VPRI_SWPRI_MAP] =                  { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_TC_ENABLE] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_PRIVATE_PAUSE_ON_WM] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_PRIVATE_PAUSE_OFF_WM] =            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_PAUSE_OFF_WM] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_PAUSE_ON_WM] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SHARED_PAUSE_ENABLE] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_TC_PC_MAP] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_PC_RXMP_MAP] =                     { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_L2_VPRI1_MAP] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_RX_PRIORITY_MAP] =                 { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_TX_PRIORITY_MAP] =                 { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SCHED_GROUPS] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SCHED_GROUP_WEIGHT] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SCHED_PRI_SETS] =                  { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_QOS_SCHED_GROUP_STRICT] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SMP_LOSSLESS_PAUSE] =                  { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SHAPING_GROUP_MAX_RATE] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SHAPING_GROUP_MIN_RATE] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SHAPING_GROUP_MAX_BURST] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_CIR_RATE] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_CIR_ACTION] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_CIR_CAPACITY] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_COLOR_SOURCE] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EIR_ACTION] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EIR_CAPACITY] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_EIR_RATE] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DSCP_MKDN_MAP] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_SWPRI_MKDN_MAP] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_DEL_POLICER] =                         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_LAG_MODE] =                            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_BCAST_RATE] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_BCAST_CAPACITY] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MCAST_RATE] =                          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MCAST_CAPACITY] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_CPU_MAC_RATE] =                        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_CPU_MAC_CAPACITY] =                    { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_IGMP_RATE] =                           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_IGMP_CAPACITY] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_ICMP_RATE] =                           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_ICMP_CAPACITY] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_RESERVED_MAC_RATE] =                   { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_RESERVED_MAC_CAPACITY] =               { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MTU_VIOL_RATE] =                       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_MTU_VIOL_CAPACITY] =                   { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_SMAC_MASK] =               { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_DMAC_MASK] =               { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_ETHERTYPE_MASK] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_VLAN_ID_1_MASK] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_VLAN_PRI_1_MASK] =         { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_SYMMETRIZE_MAC] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_USE_L3_HASH] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L2_HASH_KEY_USE_L2_IF_IP] =            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_SIP_MASK] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_DIP_MASK] =             { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_L4_SRC_MASK] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_L4_DST_MASK] =          { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_DSCP_MASK] =            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_ISL_USER_MASK] =        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_MASK] =        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_FLOW_MASK] =            { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_SYMMETRIZE_L3_FIELDS] = { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_ECMP_ROTATION] =        { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_1] =           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_2] =           { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_USE_TCP] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_USE_UDP] =              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_1] =       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_2] =       { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TX_CLASS_PAUSE] =                      { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
        [IFLA_ATTR_TXVPRI] =                              { .type = NLA_BINARY,
                                                            .size = sizeof (struct ifla_sw_attributes),},
};

static const NLTypeSystem rtnl_swport_type_system = {
        .max = ELEMENTSOF(rtnl_swport_types) - 1,
        .types = rtnl_swport_types,
};

static const NLTypeSystem rtnl_swvlan_type_system = {
        .max = ELEMENTSOF(rtnl_link_info_data_bridge_types) - 1,
        .types = rtnl_link_info_data_bridge_types,
};

static const NLType rtnl_link_types[IFLA_MAX + 1] = {
        [IFLA_ADDRESS]          = { .type = NLA_ETHER_ADDR, },
        [IFLA_BROADCAST]        = { .type = NLA_ETHER_ADDR, },
        [IFLA_IFNAME]           = { .type = NLA_STRING, .size = IFNAMSIZ - 1, },
        [IFLA_MTU]              = { .type = NLA_U32 },
        [IFLA_LINK]             = { .type = NLA_U32 },
/*
        [IFLA_QDISC],
        [IFLA_STATS],
        [IFLA_COST],
        [IFLA_PRIORITY],
*/
        [IFLA_MASTER]           = { .type = NLA_U32 },
/*
        [IFLA_WIRELESS],
        [IFLA_PROTINFO],
*/
        [IFLA_TXQLEN]           = { .type = NLA_U32 },
/*
        [IFLA_MAP]              = { .len = sizeof(struct rtnl_link_ifmap) },
*/
        [IFLA_WEIGHT]           = { .type = NLA_U32 },
        [IFLA_OPERSTATE]        = { .type = NLA_U8 },
        [IFLA_LINKMODE]         = { .type = NLA_U8 },
        [IFLA_LINKINFO]         = { .type = NLA_NESTED, .type_system = &rtnl_link_info_type_system },
        [IFLA_SWPORT_ATTRS]     = { .type = NLA_NESTED, .type_system = &rtnl_swport_type_system},
        [IFLA_NET_NS_PID]       = { .type = NLA_U32 },
        [IFLA_IFALIAS]          = { .type = NLA_STRING, .size = IFALIASZ - 1 },
        [IFLA_AF_SPEC]          = { .type = NLA_NESTED, .type_system = &rtnl_swvlan_type_system  },
/*
        [IFLA_NUM_VF],
        [IFLA_VFINFO_LIST]      = {. type = NLA_NESTED, },
        [IFLA_STATS64],
        [IFLA_VF_PORTS]         = { .type = NLA_NESTED },
        [IFLA_PORT_SELF]        = { .type = NLA_NESTED },
        [IFLA_AF_SPEC]          = { .type = NLA_NESTED },
        [IFLA_VF_PORTS],
        [IFLA_PORT_SELF],
        [IFLA_AF_SPEC],
*/
        [IFLA_GROUP]            = { .type = NLA_U32 },
        [IFLA_NET_NS_FD]        = { .type = NLA_U32 },
        [IFLA_EXT_MASK]         = { .type = NLA_U32 },
        [IFLA_PROMISCUITY]      = { .type = NLA_U32 },
        [IFLA_NUM_TX_QUEUES]    = { .type = NLA_U32 },
        [IFLA_NUM_RX_QUEUES]    = { .type = NLA_U32 },
        [IFLA_CARRIER]          = { .type = NLA_U8 },
/*
        [IFLA_PHYS_PORT_ID]     = { .type = NLA_BINARY, .len = MAX_PHYS_PORT_ID_LEN },
*/
};

static const NLTypeSystem rtnl_link_type_system = {
        .max = ELEMENTSOF(rtnl_link_types) - 1,
        .types = rtnl_link_types,
};

static const NLType rtnl_address_types[IFA_MAX + 1] = {
        [IFA_ADDRESS]           = { .type = NLA_IN_ADDR },
        [IFA_LOCAL]             = { .type = NLA_IN_ADDR },
        [IFA_LABEL]             = { .type = NLA_STRING, .size = IFNAMSIZ - 1 },
        [IFA_BROADCAST]         = { .type = NLA_IN_ADDR }, /* 6? */
        [IFA_CACHEINFO]         = { .type = NLA_CACHE_INFO, .size = sizeof(struct ifa_cacheinfo) },
/*
        [IFA_ANYCAST],
        [IFA_MULTICAST],
*/
#ifdef IFA_FLAGS
        [IFA_FLAGS]             = { .type = NLA_U32 },
#endif
};

static const NLTypeSystem rtnl_address_type_system = {
        .max = ELEMENTSOF(rtnl_address_types) - 1,
        .types = rtnl_address_types,
};

static const NLType rtnl_route_types[RTA_MAX + 1] = {
        [RTA_DST]               = { .type = NLA_IN_ADDR }, /* 6? */
        [RTA_SRC]               = { .type = NLA_IN_ADDR }, /* 6? */
        [RTA_IIF]               = { .type = NLA_U32 },
        [RTA_OIF]               = { .type = NLA_U32 },
        [RTA_GATEWAY]           = { .type = NLA_IN_ADDR },
        [RTA_PRIORITY]          = { .type = NLA_U32 },
        [RTA_PREFSRC]           = { .type = NLA_IN_ADDR }, /* 6? */
/*
        [RTA_METRICS]           = { .type = NLA_NESTED },
        [RTA_MULTIPATH]         = { .len = sizeof(struct rtnexthop) },
*/
        [RTA_FLOW]              = { .type = NLA_U32 }, /* 6? */
/*
        RTA_CACHEINFO,
        RTA_TABLE,
        RTA_MARK,
        RTA_MFC_STATS,
*/
};

static const NLTypeSystem rtnl_route_type_system = {
        .max = ELEMENTSOF(rtnl_route_types) - 1,
        .types = rtnl_route_types,
};

static const NLType rtnl_neigh_types[NDA_MAX + 1] = {
        [NDA_DST]               = { .type = NLA_IN_ADDR },
        [NDA_LLADDR]            = { .type = NLA_ETHER_ADDR },
        [NDA_CACHEINFO]         = { .type = NLA_CACHE_INFO, .size = sizeof(struct nda_cacheinfo) },
        [NDA_PROBES]            = { .type = NLA_U32 },
        [NDA_VLAN]              = { .type = NLA_U16 },
        [NDA_PORT]              = { .type = NLA_U16 },
        [NDA_VNI]               = { .type = NLA_U32 },
        [NDA_IFINDEX]           = { .type = NLA_U32 },
};

static const NLTypeSystem rtnl_neigh_type_system = {
        .max = ELEMENTSOF(rtnl_neigh_types) - 1,
        .types = rtnl_neigh_types,
};

static const NLType rtnl_types[RTM_MAX + 1] = {
        [NLMSG_DONE]   = { .type = NLA_META, .size = 0 },
        [NLMSG_ERROR]  = { .type = NLA_META, .size = sizeof(struct nlmsgerr) },
        [RTM_NEWLINK]  = { .type = NLA_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_DELLINK]  = { .type = NLA_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_GETLINK]  = { .type = NLA_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_SETLINK]  = { .type = NLA_NESTED, .type_system = &rtnl_link_type_system, .size = sizeof(struct ifinfomsg) },
        [RTM_NEWADDR]  = { .type = NLA_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_DELADDR]  = { .type = NLA_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_GETADDR]  = { .type = NLA_NESTED, .type_system = &rtnl_address_type_system, .size = sizeof(struct ifaddrmsg) },
        [RTM_NEWROUTE] = { .type = NLA_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_DELROUTE] = { .type = NLA_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_GETROUTE] = { .type = NLA_NESTED, .type_system = &rtnl_route_type_system, .size = sizeof(struct rtmsg) },
        [RTM_NEWNEIGH] = { .type = NLA_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_DELNEIGH] = { .type = NLA_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
        [RTM_GETNEIGH] = { .type = NLA_NESTED, .type_system = &rtnl_neigh_type_system, .size = sizeof(struct ndmsg) },
};

const NLTypeSystem rtnl_type_system = {
        .max = ELEMENTSOF(rtnl_types) - 1,
        .types = rtnl_types,
};

int type_system_get_type(const NLTypeSystem *type_system, const NLType **ret, uint16_t type) {
        const NLType *nl_type;

        assert(ret);

        if (!type_system)
                type_system = &rtnl_type_system;

        assert(type_system->types);

        if (type > type_system->max)
                return -ENOTSUP;

        nl_type = &type_system->types[type];

        if (nl_type->type == NLA_UNSPEC)
                return -ENOTSUP;

        *ret = nl_type;

        return 0;
}

int type_system_get_type_system(const NLTypeSystem *type_system, const NLTypeSystem **ret, uint16_t type) {
        const NLType *nl_type;
        int r;

        assert(ret);

        r = type_system_get_type(type_system, &nl_type, type);
        if (r < 0)
                return r;

        assert_return(nl_type->type == NLA_NESTED, -EINVAL);

        assert(nl_type->type_system);

        *ret = nl_type->type_system;

        return 0;
}

int type_system_get_type_system_union(const NLTypeSystem *type_system, const NLTypeSystemUnion **ret, uint16_t type) {
        const NLType *nl_type;
        int r;

        assert(ret);

        r = type_system_get_type(type_system, &nl_type, type);
        if (r < 0)
                return r;

        assert_return(nl_type->type == NLA_UNION, -EINVAL);

        assert(nl_type->type_system_union);

        *ret = nl_type->type_system_union;

        return 0;
}

int type_system_union_get_type_system(const NLTypeSystemUnion *type_system_union, const NLTypeSystem **ret, const char *key) {
        int type;

        assert(type_system_union);
        assert(type_system_union->lookup);
        assert(type_system_union->type_systems);
        assert(ret);
        assert(key);

        type = type_system_union->lookup(key);
        if (type < 0)
                return -ENOTSUP;

        assert(type < type_system_union->num);

        *ret = &type_system_union->type_systems[type];

        return 0;
}
