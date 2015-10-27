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
#include <netinet/in.h>
#include <linux/if_bridge.h>

#include "networkd.h"
#include "networkd-netdev.h"
#include "networkd-link.h"
#include "network-internal.h"
#include "path-util.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "util.h"
#include "fileio.h"
#include "rtnl-internal.h"

#define VLAN_N_VID    4096
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

typedef int (*t_set_attr)(SWPort *swport, SWPortAttrType attr, unsigned value);
typedef unsigned (*t_get_attr)(SWPort *swport, SWPortAttrType attr);

typedef struct SWPortAttrInfo {
        int ifla_attr; /* corresponding ifla attribute */
        const char* name; /* attribute name as in swport config file */
        const char* sys_name; /* attribute name to read from sysfs */
} SWPortAttrInfo;


static int swport_set_rtnl_attr(SWPort *swport, int attr, int index, u_int64_t value);
static int swport_get_vlans(Manager *manager);
static int swport_set_vlan (SWPort *swport, SWPortVlanEntry *vlan_entry);
static int swport_del_vlan(SWPort *swport, uint16_t vid);
int vlan_entry_new(SWPort *const swport, const unsigned section, SWPortVlanEntry **ret);
const char *qosattr_ifla_to_string(int d) _const_;
int qosattr_ifla_from_string(const char *d) _pure_;

static const SWPortAttrInfo swport_attrs[SWPORT_ATTR_COUNT] = {

        [SWPORT_ATTR_DEF_CFI] =
        { IFLA_ATTR_DEF_CFI, "DefCfi", "def_cfi",},
        [SWPORT_ATTR_DEF_DSCP] =
        { IFLA_ATTR_DEF_DSCP, "DefDscp", "def_dscp",},
        [SWPORT_ATTR_DEF_PRI] =
        { IFLA_ATTR_DEF_PRI, "DefPri", "def_pri",},
        [SWPORT_ATTR_DEF_SWPRI] =
        { IFLA_ATTR_DEF_SWPRI, "DefSwpri", "def_swpri",},
        [SWPORT_ATTR_DROP_BV] =
        { IFLA_ATTR_DROP_BV, "DropBv", "drop_bv",},
        [SWPORT_ATTR_DROP_TAGGED] =
        { IFLA_ATTR_DROP_TAGGED, "DropTagged", "drop_tagged",},
        [SWPORT_ATTR_EEE_MODE] =
        { IFLA_ATTR_EEE_MODE, "EeeMode", "eee_mode",},
        [SWPORT_ATTR_EEE_TX_ACTIVITY_TIMEOUT] =
        { IFLA_ATTR_EEE_TX_ACTIVITY_TIMEOUT, "EeeTxActivityTimeout", "eee_tx_activity_timeout",},
        [SWPORT_ATTR_EEE_TX_LPI_TIMEOUT] =
        { IFLA_ATTR_EEE_TX_LPI_TIMEOUT, "EeeTxLpiTimeout", "eee_tx_lpi_timeout",},
        [SWPORT_ATTR_LOOPBACK] =
        { IFLA_ATTR_LOOPBACK, "Loopback", "loopback",},
        [SWPORT_ATTR_FABRIC_LOOPBACK] =
        { IFLA_ATTR_FABRIC_LOOPBACK, "FabricLoopback", "fabric_loopback",},
        [SWPORT_ATTR_IGNORE_IFG_ERRORS] =
        { IFLA_ATTR_IGNORE_IFG_ERRORS, "IgnoreIfgErrors", "ignore_ifg_errors",},
        [SWPORT_ATTR_LEARNING] =
        { IFLA_ATTR_LEARNING, "Learning", "learning",},
        [SWPORT_ATTR_PARSE_MPLS] =
        { IFLA_ATTR_PARSE_MPLS, "ParseMpls", "parse_mpls",},
        [SWPORT_ATTR_PARSER] =
        { IFLA_ATTR_PARSER, "Parser", "parser",},
        [SWPORT_ATTR_PARSER_STORE_MPLS] =
        { IFLA_ATTR_PARSER_STORE_MPLS, "ParserStoreMpls", "parser_store_mpls",},
        [SWPORT_ATTR_PARSER_VLAN1_TAG] =
        { IFLA_ATTR_PARSER_VLAN1_TAG, "ParserVlan1Tag", "vlan1_tag",},
        [SWPORT_ATTR_TAGGING] =
        { IFLA_ATTR_TAGGING, "Tagging", "tagging",},
        [SWPORT_ATTR_TIMESTAMP_GENERATION] =
        { IFLA_ATTR_TIMESTAMP_GENERATION, "TimestampGeneration", "timestamp_generation",},
        [SWPORT_ATTR_UPDATE_DSCP] =
        { IFLA_ATTR_UPDATE_DSCP, "UpdateDscp", "update_dscp",},
        [SWPORT_ATTR_UPDATE_TTL] =
        { IFLA_ATTR_UPDATE_TTL, "UpdateTtl", "update_ttl",},
        [SWPORT_ATTR_AUTONEG] =
        { IFLA_ATTR_AUTONEG, "Autoneg", "autoneg",},
        [SWPORT_ATTR_AUTONEG_BASEPAGE] =
        { IFLA_ATTR_AUTONEG_BASEPAGE, "AutonegBasepage", "autoneg_basepage",},
        [SWPORT_ATTR_AUTONEG_LINK_INHB_TIMER] =
        { IFLA_ATTR_AUTONEG_LINK_INHB_TIMER, "AutonegLinkInhbTimer", "autoneg_link_inhb_timer",},
        [SWPORT_ATTR_AUTONEG_LINK_INHB_TIMER_KX] =
        { IFLA_ATTR_AUTONEG_LINK_INHB_TIMER_KX, "AutonegLinkInhbTimerKx", "autoneg_link_inhb_timer_kx",},
        [SWPORT_ATTR_REPLACE_DSCP] =
        { IFLA_ATTR_REPLACE_DSCP, "ReplaceDscp", "replace_dscp",},
        [SWPORT_ATTR_ROUTED_FRAME_UPDATE_FIELDS] =
        { IFLA_ATTR_ROUTED_FRAME_UPDATE_FIELDS, "RoutedFrameUpdateFields", "routed_frame_update_fields",},
        [SWPORT_ATTR_RX_CLASS_PAUSE] =
        { IFLA_ATTR_RX_CLASS_PAUSE, "RxClassPause", "rx_class_pause",},
        [SWPORT_ATTR_RX_CUT_THROUGH] =
        { IFLA_ATTR_RX_CUT_THROUGH, "RxCutThrough", "rx_cut_through",},
        [SWPORT_ATTR_SWPRI_DSCP_PREF] =
        { IFLA_ATTR_SWPRI_DSCP_PREF, "SwpriDscpPref", "swpri_dscp_pref",},
        [SWPORT_ATTR_SWPRI_SOURCE] =
        { IFLA_ATTR_SWPRI_SOURCE, "SwpriSource", "swpri_source",},
        [SWPORT_ATTR_TX_CUT_THROUGH] =
        { IFLA_ATTR_TX_CUT_THROUGH, "TxCutThrough", "tx_cut_through",},
        [SWPORT_ATTR_PAUSE_MODE] =
        { IFLA_ATTR_PAUSE_MODE, "PauseMode", "pause_mode",},
        [SWPORT_ATTR_DEF_PRI2] =
        { IFLA_ATTR_DEF_PRI2, "DefPri2", "def_pri2",},
        [SWPORT_ATTR_DEF_VLAN2] =
        { IFLA_ATTR_DEF_VLAN2, "DefVlan2", "def_vlan2",},
        [SWPORT_ATTR_DOT1X_STATE] =
        { IFLA_ATTR_DOT1X_STATE, "Dot1xState", "dot1x_state",},
        [SWPORT_ATTR_PARSER_VLAN2_TAG] =
        { IFLA_ATTR_PARSER_VLAN2_TAG, "ParserVlan2Tag", "parser_vlan2_tag",},
        [SWPORT_ATTR_SECURITY_ACTION] =
        { IFLA_ATTR_SECURITY_ACTION, "SecurityAction", "security_action",},
        [SWPORT_ATTR_TAGGING2] =
        { IFLA_ATTR_TAGGING2, "Tagging2", "tagging2",},
        [SWPORT_ATTR_BCAST_FLOODING] =
        { IFLA_ATTR_BCAST_FLOODING, "BcastFlooding", "bcast_flooding",},
        [SWPORT_ATTR_UCAST_FLOODING] =
        { IFLA_ATTR_UCAST_FLOODING, "UcastFlooding", "ucast_flooding",},
        [SWPORT_ATTR_MCAST_FLOODING] =
        { IFLA_ATTR_MCAST_FLOODING, "McastFlooding", "mcast_flooding",},
        [SWPORT_ATTR_MCAST_PRUNING] =
        { IFLA_ATTR_MCAST_PRUNING, "McastPruning", "mcast_pruning",},
        [SWPORT_ATTR_BCAST_PRUNING] =
        { IFLA_ATTR_BCAST_PRUNING, "BcastPruning", "bcast_pruning",},
        [SWPORT_ATTR_UCAST_PRUNING] =
        { IFLA_ATTR_UCAST_PRUNING, "UcastPruning", "ucast_pruning",},
        [SWPORT_ATTR_MAC_TABLE_ADDRESS_AGING_TIME] =
        { IFLA_ATTR_MAC_TABLE_ADDRESS_AGING_TIME, "MacTableAddressAgingTime", "mac_table_address_aging_time",},
        [SWPORT_ATTR_MAX_FRAME_SIZE] =
        { IFLA_ATTR_MAX_FRAME_SIZE, "MaxFrameSize", "max_frame_size",},
        [SWPORT_ATTR_LAG_MODE] =
        { IFLA_ATTR_LAG_MODE, "LagMode", "lag_mode",},
        [SWPORT_ATTR_L2_HASH_KEY_SMAC_MASK] =
        { IFLA_ATTR_L2_HASH_KEY_SMAC_MASK, "SmacMask", "smac_mask",},
        [SWPORT_ATTR_L2_HASH_KEY_DMAC_MASK] =
        { IFLA_ATTR_L2_HASH_KEY_DMAC_MASK, "DmacMask", "dmac_mask",},
        [SWPORT_ATTR_L2_HASH_KEY_ETHERTYPE_MASK] =
        { IFLA_ATTR_L2_HASH_KEY_ETHERTYPE_MASK, "EthertypeMask", "ethertype_mask",},
        [SWPORT_ATTR_L2_HASH_KEY_VLAN_ID_1_MASK] =
        { IFLA_ATTR_L2_HASH_KEY_VLAN_ID_1_MASK, "VlanId1Mask", "vlan_id_1_mask",},
        [SWPORT_ATTR_L2_HASH_KEY_VLAN_PRI_1_MASK] =
        { IFLA_ATTR_L2_HASH_KEY_VLAN_PRI_1_MASK, "VlanPri1Mask", "vlan_pri_1_mask",},
        [SWPORT_ATTR_L2_HASH_KEY_SYMMETRIZE_MAC] =
        { IFLA_ATTR_L2_HASH_KEY_SYMMETRIZE_MAC, "SymmetrizeMac", "symmetrize_mac",},
        [SWPORT_ATTR_L2_HASH_KEY_USE_L3_HASH] =
        { IFLA_ATTR_L2_HASH_KEY_USE_L3_HASH, "UseL3Hash", "use_l3_hash",},
        [SWPORT_ATTR_L2_HASH_KEY_USE_L2_IF_IP] =
        { IFLA_ATTR_L2_HASH_KEY_USE_L2_IF_IP, "UseL2IfIp", "use_l2_if_ip",},
        [SWPORT_ATTR_L3_HASH_CONFIG_SIP_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_SIP_MASK, "SipMask", "sip_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_DIP_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_DIP_MASK, "DipMask", "dip_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_L4_SRC_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_L4_SRC_MASK, "L4SrcMask", "l4_src_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_L4_DST_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_L4_DST_MASK, "L4DstMask", "l4_dst_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_DSCP_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_DSCP_MASK, "DscpMask", "dscp_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_ISL_USER_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_ISL_USER_MASK, "IslUserMask", "isl_user_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_PROTOCOL_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_MASK, "ProtocolMask", "protocol_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_FLOW_MASK] =
        { IFLA_ATTR_L3_HASH_CONFIG_FLOW_MASK, "FlowMask", "flow_mask",},
        [SWPORT_ATTR_L3_HASH_CONFIG_SYMMETRIZE_L3_FIELDS] =
        { IFLA_ATTR_L3_HASH_CONFIG_SYMMETRIZE_L3_FIELDS, "SymmetrizeL3Fields", "symmetrize_l3_fields",},
        [SWPORT_ATTR_L3_HASH_CONFIG_ECMP_ROTATION] =
        { IFLA_ATTR_L3_HASH_CONFIG_ECMP_ROTATION, "EcmpRotation", "ecmp_rotation",},
        [SWPORT_ATTR_L3_HASH_CONFIG_PROTOCOL_1] =
        { IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_1, "Protocol1", "protocol_1",},
        [SWPORT_ATTR_L3_HASH_CONFIG_PROTOCOL_2] =
        { IFLA_ATTR_L3_HASH_CONFIG_PROTOCOL_2, "Protocol2", "protocol_2",},
        [SWPORT_ATTR_L3_HASH_CONFIG_USE_TCP] =
        { IFLA_ATTR_L3_HASH_CONFIG_USE_TCP, "UseTcp", "use_tcp",},
        [SWPORT_ATTR_L3_HASH_CONFIG_USE_UDP] =
        { IFLA_ATTR_L3_HASH_CONFIG_USE_UDP, "UseUdp", "use_udp",},
        [SWPORT_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_1] =
        { IFLA_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_1, "UseProtocol1", "use_protocol_1",},
        [SWPORT_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_2] =
        { IFLA_ATTR_L3_HASH_CONFIG_USE_PROTOCOL_2, "UseProtocol2", "use_protocol_2",},
        [SWPORT_ATTR_BCAST_RATE] =
        {IFLA_ATTR_BCAST_RATE, "BcastRate", "bcast_rate",},
        [SWPORT_ATTR_BCAST_CAPACITY] =
        {IFLA_ATTR_BCAST_CAPACITY, "BcastCapacity", "bcast_capacity",},
        [SWPORT_ATTR_MCAST_RATE] =
        {IFLA_ATTR_MCAST_RATE, "McastRate", "mcast_rate",},
        [SWPORT_ATTR_MCAST_CAPACITY] =
        {IFLA_ATTR_MCAST_CAPACITY, "McastCapacity", "mcast_capacity",},
        [SWPORT_ATTR_CPU_MAC_RATE] =
        {IFLA_ATTR_CPU_MAC_RATE, "CpuMacRate", "cpu_mac_rate",},
        [SWPORT_ATTR_CPU_MAC_CAPACITY] =
        {IFLA_ATTR_CPU_MAC_CAPACITY, "CpuMacCapacity", "cpu_mac_capacity",},
        [SWPORT_ATTR_IGMP_RATE] =
        {IFLA_ATTR_IGMP_RATE, "IgmpRate", "igmp_rate",},
        [SWPORT_ATTR_IGMP_CAPACITY] =
        {IFLA_ATTR_IGMP_CAPACITY, "IgmpCapacity", "igmp_capacity",},
        [SWPORT_ATTR_ICMP_RATE] =
        {IFLA_ATTR_ICMP_RATE, "IcmpRate", "icmp_rate",},
        [SWPORT_ATTR_ICMP_CAPACITY] =
        {IFLA_ATTR_ICMP_CAPACITY, "IcmpCapacity", "icmp_capacity",},
        [SWPORT_ATTR_RESERVED_MAC_RATE] =
        {IFLA_ATTR_RESERVED_MAC_RATE, "ReservedMacRate", "reserved_mac_rate",},
        [SWPORT_ATTR_RESERVED_MAC_CAPACITY] =
        {IFLA_ATTR_RESERVED_MAC_CAPACITY, "ReservedMacCapacity", "reserved_mac_capacity",},
        [SWPORT_ATTR_MTU_VIOL_RATE] =
        {IFLA_ATTR_MTU_VIOL_RATE, "MtuViolRate", "mtu_viol_rate",},
        [SWPORT_ATTR_MTU_VIOL_CAPACITY] =
        {IFLA_ATTR_MTU_VIOL_CAPACITY, "MtuViolCapacity", "mtu_viol_capacity",},
        [SWPORT_ATTR_TX_CLASS_PAUSE] =
        {IFLA_ATTR_TX_CLASS_PAUSE, "TxClassPause", "tx_class_pause",},
        [SWPORT_ATTR_SMP_LOSSLESS_PAUSE] =
        {IFLA_ATTR_SMP_LOSSLESS_PAUSE, "SmpLosslessPause", "smp_lossless_pause",},
        [SWPORT_ATTR_TXVPRI] =
        {IFLA_ATTR_TXVPRI, "TxVPri", "txvpri",},
};

static const char* const qosattr_ifla_table[__IFLA_ATTR_MAX] = {
        [IFLA_ATTR_QOS_DSCP_SWPRI_MAP] = "DscpSwpriMap",
        [IFLA_ATTR_QOS_GLOBAL_USAGE] = "GlobalUsage",
        [IFLA_ATTR_QOS_SWPRI_TC_MAP] = "SwpriTcMap",
        [IFLA_ATTR_QOS_TC_SMP_MAP] = "TcSmpMap",
        [IFLA_ATTR_QOS_TRAP_CLASS_SWPRI_MAP] = "TrapClassSwpriMap",
        [IFLA_ATTR_QOS_VPRI_SWPRI_MAP] = "VpriSwpriMap",
        [IFLA_ATTR_QOS_TC_ENABLE] = "TcEnable",
        [IFLA_ATTR_QOS_TC_PC_MAP] = "TcPcMap",
        [IFLA_ATTR_QOS_PC_RXMP_MAP] = "PcRxmpMap",
        [IFLA_ATTR_QOS_RX_PRIORITY_MAP] = "RxPriorityMap",
        [IFLA_ATTR_QOS_TX_PRIORITY_MAP] = "TxPriorityMap",
        [IFLA_ATTR_QOS_SCHED_GROUP_WEIGHT] = "SchedGroupWeight",
        [IFLA_ATTR_QOS_SCHED_GROUP_STRICT] = "SchedGroupStrict",
        [IFLA_ATTR_SHAPING_GROUP_MAX_RATE] = "ShapingGroupMaxRate",
        [IFLA_ATTR_SHAPING_GROUP_MIN_RATE] = "ShapingGroupMinRate",
        [IFLA_ATTR_SHAPING_GROUP_MAX_BURST] = "ShapingGroupMaxBurst",
        [IFLA_ATTR_CIR_RATE] = "CirRate",
        [IFLA_ATTR_CIR_ACTION] = "CirAction",
        [IFLA_ATTR_CIR_CAPACITY] = "CirCapacity",
        [IFLA_ATTR_COLOR_SOURCE] = "ColorSource",
        [IFLA_ATTR_EIR_ACTION] = "EirAction",
        [IFLA_ATTR_EIR_CAPACITY] = "EirCapacity",
        [IFLA_ATTR_EIR_RATE] = "EirRate",
        [IFLA_ATTR_DSCP_MKDN_MAP] = "DscpMkdnMap",
        [IFLA_ATTR_SWPRI_MKDN_MAP] = "SwpriMkdnMap",
        [IFLA_ATTR_MKDN_DSCP] = "MkdnDscp",
        [IFLA_ATTR_MKDN_SWPRI] = "MkdnSwpri",
        [IFLA_ATTR_DEL_POLICER] = "DelPolicer",
};

DEFINE_STRING_TABLE_LOOKUP(qosattr_ifla, int);
int swport_attrs_count = ELEMENTSOF(swport_attrs);

int vlan_entry_new(SWPort *const swport,
                         const unsigned section,
                         SWPortVlanEntry **ret) {
        _cleanup_vlanentry_free_ SWPortVlanEntry *vlan_entry = NULL;

        assert(swport);

        /* search entry in hashmap first. */
        if(section) {
                vlan_entry = hashmap_get(swport->vlan_entries_by_section, UINT_TO_PTR(section));
                if (vlan_entry) {
                        *ret = vlan_entry;
                        vlan_entry = NULL;

                        return 0;
                }
        }

        /* allocate space for a new vlan entry. */
        vlan_entry = new0(SWPortVlanEntry, 1);
        if (!vlan_entry)
               return log_oom();

        /* init vlan structure. */
        vlan_entry->swport = swport;
        vlan_entry->EgressUntagged = false;
        vlan_entry->pvid = false;

        LIST_PREPEND(swport_vlan_enties, swport->vlan_entries, vlan_entry);

        if (section) {
                vlan_entry->section = section;
                hashmap_put(swport->vlan_entries_by_section,
                            UINT_TO_PTR(vlan_entry->section), vlan_entry);
        }

        /* return allocated vlan structure. */
        *ret = vlan_entry;
        vlan_entry = NULL;

        return 0;
}

/* remove vlan entry. */
void vlan_entry_free(SWPortVlanEntry *vlan_entry) {
        if(!vlan_entry)
                return;

        if(vlan_entry->swport) {
                LIST_REMOVE(swport_vlan_enties, vlan_entry->swport->vlan_entries,
                            vlan_entry);

                if(vlan_entry->section)
                    hashmap_remove(vlan_entry->swport->vlan_entries_by_section,
                                   UINT_TO_PTR(vlan_entry->section));
        }

        free(vlan_entry);
}

static void swport_dump_one(SWPort *swport) {
        int i;
        if (!swport)
                return;

        log_debug("  Port=%s", swport->match_name);
        for (i = 0; i < swport_attrs_count; i++) {
                log_debug("    %s=%" PRIu64, swport_attrs[i].name, swport->attrs[i].value);
        }
}

static void swport_dump(SWPort *swports) {
        SWPort *swport;

        if (!swports)
                return;

        LIST_FOREACH(swports, swport, swports)
        swport_dump_one(swport);
}

static void swport_merge_config(SWPort *swport, SWPort *default_swports) {
        int i;
        SWPort *default_swport;
        if (!swport || !default_swports)
                return;

        LIST_FOREACH(swports, default_swport, default_swports) {
                if (strcmp(default_swport->match_name, swport->match_name) == 0) {
                        for (i = 0; i < swport_attrs_count; i++) {
                                if (!swport->attrs[i].flag && default_swport->attrs[i].flag) {
                                        swport->attrs[i].value = default_swport->attrs[i].value;
                                        swport->attrs[i].flag = true;
                                }
                        }
                        break;
                }
        }
}

static int swport_load_one(Manager *manager, const char *filename, SWPort **swports) {
        SWPort *swport = NULL;
        _cleanup_fclose_ FILE *file = NULL;
        int r;

        log_debug("Loading swport configuration file (%s)", filename);

        assert(manager);
        assert(filename);

        file = fopen(filename, "re");
        if (!file) {
                if (errno == ENOENT)
                        return 0;
                else
                        return -errno;
        }

        if (null_or_empty_fd(fileno(file))) {
                log_debug("Skipping empty file: %s", filename);
                return 0;
        }

        swport = new0(SWPort, 1);
        if (!swport)
                return log_oom();

        swport->manager = manager;
        swport->vlan_entries_by_section = hashmap_new(NULL);
        if (!swport->vlan_entries_by_section)
                return log_oom();

        swport->existing_vlan_entries_by_vid = hashmap_new(NULL);
        if (!swport->existing_vlan_entries_by_vid)
                return log_oom();

        LIST_HEAD_INIT(swport->vlan_entries);
        LIST_HEAD_INIT(swport->qos_attrs);

        swport->vlans_configured = false;

        r = config_parse(NULL, filename, file,
                "Match\0SWPortAttrs\0Vlan\0QosAttrs\0L2HashKey\0L3HashConfig\0RateLimit\0",
                config_item_perf_lookup, network_swport_gperf_lookup,
                false, false, true, swport);

        if (r < 0)
                return r;

        if (!swport->match_name) {

                log_info("Missing Name in [Match] section, skipping configuration file %s.", filename);
                swport_free(swport);
                return 0;
        }

        LIST_PREPEND(swports, *swports, swport);

        return 0;
}

int swport_load(Manager *m) {
        SWPort *swport;
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(m);
        assert(SWPORT_ATTR_COUNT == swport_attrs_count);

        while ((swport = m->default_swports)) {
                LIST_REMOVE(swports, m->default_swports, swport);
                swport_free(swport);
        }

        r = conf_files_list_strv(&files, ".default-swport", NULL, network_dirs);
        if (r < 0) {
                log_error("Failed to enumerate default-swport files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = swport_load_one(m, *f, &m->default_swports);
                if (r < 0)
                        return r;
        }

        log_debug("Ports default configuration:");
        swport_dump(m->default_swports);

        while ((swport = m->swports)) {
                LIST_REMOVE(swports, m->swports, swport);
                swport_free(swport);
        }

        r = conf_files_list_strv(&files, ".swport", NULL, network_dirs);
        if (r < 0) {
                log_error("Failed to enumerate swport files: %s", strerror(-r));
                return r;
        }

        STRV_FOREACH_BACKWARDS(f, files) {
                r = swport_load_one(m, *f, &m->swports);
                if (r < 0)
                        return r;
        }

        log_debug("Merged Ports configuration:");

        LIST_FOREACH(swports, swport, m->swports) {
                swport_merge_config(swport, m->default_swports);
        }

        swport_dump(m->swports);

        swport_get_vlans(m);

        return 0;
}

void swport_free(SWPort *swport) {
        SWPortVlanEntry *vlan_entry;
        SWPortQoSAttrs *qos_attr, *qos_attr_next;

        if (!swport)
                return;

        free(swport->match_name);
        while ((vlan_entry = swport->vlan_entries))
                vlan_entry_free(vlan_entry);
        hashmap_free(swport->vlan_entries_by_section);
        hashmap_free_free(swport->existing_vlan_entries_by_vid);

        LIST_FOREACH_SAFE(swport_qos_attrs, qos_attr, qos_attr_next, swport->qos_attrs) {
                LIST_REMOVE(swport_qos_attrs, swport->qos_attrs, qos_attr);
                free(qos_attr);
        }

        free(swport);
}

int swport_apply_attributes(SWPort *swport) {
        Link *link;
        SWPortVlanEntry *vlan_entry;
        SWPortQoSAttrs *qos_attrs;
        struct bridge_vlan_info *vinfo;
        Iterator it;
        int i;
        int r;

        log_debug("Configuring switch port attributes (port: %s)", swport->match_name);

        HASHMAP_FOREACH(link, swport->manager->links, it) {
                if (strcmp(link->ifname, swport->match_name) == 0) {
                        swport->link = link;
                        break;
                }
        }

        if (swport->link == NULL) {
                log_error("Unable to configure switchport settings for interface: %s, unable to find ifindex", swport->match_name);
                return -EINVAL;
        }

        for (i = 0; i < swport_attrs_count; i++) {
                if (!swport->attrs[i].flag)
                        continue;
                r = swport_set_rtnl_attr(swport, swport_attrs[i].ifla_attr, -1, swport->attrs[i].value);
                if (r < 0) {
                        log_error("Unable to set attribute %s on %s  %s", swport_attrs[i].name, swport->match_name, strerror(-r));
                        return r;
                }
        }

        LIST_FOREACH(swport_qos_attrs, qos_attrs, swport->qos_attrs) {
                r = swport_set_rtnl_attr(swport, qos_attrs->ifla_attr, qos_attrs->index, qos_attrs->value);
                if(r < 0) {
                        log_error_link(link, "Failed to set QoS attribute: %d %s", qos_attrs->ifla_attr, strerror(-r));
                        break;
                }
        }

        if (!swport->vlans_configured) {
                LIST_FOREACH(swport_vlan_enties, vlan_entry, swport->vlan_entries) {
                        r = swport_set_vlan(swport, vlan_entry);
                        if(r < 0) {
                                log_error_link(link, "Failed to add MAC entry to static MAC table: %s", strerror(-r));
                                break;
                        }
                }

                HASHMAP_FOREACH(vinfo, swport->existing_vlan_entries_by_vid, it) {
                        bool found = false;
                        LIST_FOREACH(swport_vlan_enties, vlan_entry, swport->vlan_entries) {
                                if ((found = (vinfo->vid == vlan_entry->vid)))
                                        break;
                        }

                        if (!found) {
                                r = swport_del_vlan(swport, vinfo->vid);
                                if (r < 0) {
                                        log_error_link(link, "Failed to delete switch port VLANs: %s", strerror(-r));
                                        return r;
                                }
                        }
                }

                swport->vlans_configured = true;
        }

        return 0;
}

static int swport_set_rtnl_attr(SWPort *swport, int attr, int index, u_int64_t value) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;
        struct ifla_sw_attributes attr_val_index;
        attr_val_index.attribute_index = index;

        log_debug("Setting ifindex: %u, setting IFLA attribute %d to %" PRIu64" index %d", swport->link->ifindex, attr, value, index);

        r = sd_rtnl_message_new_link(swport->link->manager->rtnl, &req, RTM_SETLINK, swport->link->ifindex);

        if (r < 0) {
                log_error_link(swport->link, "Could not allocate RTM_SETLINK message");
                return r;
        }

        r = sd_rtnl_message_open_container(req, IFLA_SWPORT_ATTRS);

        if (r < 0) {
                log_error_link(swport->link, "sd_rtnl_message_open_container %d: %s", attr, strerror(-r));
                return r;
        }
        attr_val_index.attribute_val = value;

        r = sd_rtnl_message_append_binary(req, attr, &attr_val_index, sizeof(struct ifla_sw_attributes));

        if (r < 0) {
                log_error_link(swport->link, "sd_rtnl_message_append_u32 %d: %s", attr, strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(req);

        if (r < 0) {
                log_error_link(swport->link, "sd_rtnl_message_close_container %d: %s", attr, strerror(-r));
                return r;
        }

        r = sd_rtnl_call(swport->link->manager->rtnl, req, 0, NULL);

        if (r < 0) {
                log_error_link(swport->link, "Failed to set IFLA attribute %d, Could not send rtnetlink message: %s", attr, strerror(-r));
                return r;
        }
        return 0;
}

static int swport_get_vlans(Manager *manager) {
        int r, i;
        SWPort *swport;
        const char *ifname;
        struct bridge_vlan_info *vi;
        struct bridge_vlan_info vinfo[VLAN_N_VID];
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL, *vlan = NULL;

        assert(manager);
        assert(manager->rtnl);

        r = sd_rtnl_message_new_vlan(manager->rtnl, &req,
                                     RTM_GETLINK, 0);
        if (r < 0) {
                log_error("Could not allocate RTM_GETLINK message");
                return r;
        }

        r = sd_rtnl_message_request_dump(req, true);
        if (r < 0) {
                log_error("Could not request dump: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u32(req, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN);
        if (r < 0) {
                log_error("Could not append IFLA_EXT_MASK attribute: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call(manager->rtnl, req, 0, &reply);
        if (r < 0) {
                log_error("Could not send request: %s", strerror(-r));
                return r;
        }

        LIST_FOREACH(swports, swport, manager->swports) {
                for (vlan = reply; vlan; vlan = sd_rtnl_message_next(vlan)) {

                        r = sd_rtnl_message_read_string(vlan,IFLA_IFNAME, &ifname);
                        if (r < 0) {
                                log_error("Could not get ifname: %s", strerror(-r));
                                return r;
                        }

                        if (!streq(swport->match_name, ifname))
                                continue;

                        r = sd_rtnl_message_get_errno(vlan);
                        if (r < 0) {
                                log_error("Could not dump link VLAN info: %s", strerror(-r));
                                return r;
                        }

                        r = sd_rtnl_message_enter_container(vlan, IFLA_AF_SPEC);
                        if (r < 0)
                                continue;

                        r = sd_rtnl_message_read_binary(vlan, IFLA_AF_SPEC, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof (*vinfo), ARRAY_SIZE(vinfo));
                        if (r < 0 || r == 0)
                                continue;

                        for (i = r - 1; i >= 0; --i) {
                                vi = newdup(struct bridge_vlan_info, (vinfo + i), 1);
                                if (!vi)
                                        return log_oom();

                                r = hashmap_put(swport->existing_vlan_entries_by_vid, UINT_TO_PTR(vi->vid), vi);
                                if (r < 0) {
                                        log_error("Could not put VLAN info to hashmap: %s", strerror(-r));
                                        return r;
                                }
                        }

                        r = sd_rtnl_message_exit_container(vlan);
                        if (r < 0)
                                log_error("Could not exit IFLA_AF_SPEC container: %s", strerror(-r));
                }
        }

        return 0;
}

static int swport_set_vlan(SWPort *swport, SWPortVlanEntry *vlan_entry) {
        int r;
        uint16_t br_flags = 0, vlan_flags = 0;
        struct bridge_vlan_info vinfo, *exist_vlan;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;

        assert(swport->link);
        assert(swport->link->manager->rtnl);
        assert(vlan_entry);

        br_flags |= BRIDGE_FLAGS_SELF;
        if (vlan_entry->EgressUntagged)
            vlan_flags |= BRIDGE_VLAN_INFO_UNTAGGED;

        if (vlan_entry->pvid)
            vlan_flags |= BRIDGE_VLAN_INFO_PVID;

        exist_vlan = hashmap_get(swport->existing_vlan_entries_by_vid, UINT_TO_PTR(vlan_entry->vid));

        if (exist_vlan) {
                if (exist_vlan->flags == vlan_flags)
                        return 0;
                else {
                        r = swport_del_vlan(swport, exist_vlan->vid);
                        if (r < 0) {
                                log_error_link(swport->link, "Could not delete VLAN %d: %s",
                                                exist_vlan->vid, strerror(-r));
                                return r;
                        }
                }
        }

        memset(&vinfo, 0, sizeof(vinfo));

        r = sd_rtnl_message_new_vlan(swport->link->manager->rtnl, &req,
                                     RTM_SETLINK, swport->link->ifindex);
        if (r < 0) {
                log_error_link(swport->link, "Could not allocate RTM_SETLINK message: %s",
                                strerror(-r));
                return r;
        }

        r = sd_rtnl_message_open_container(req, IFLA_AF_SPEC);
        if (r < 0) {
                log_error_link(swport->link, "Could not open IFLA_AF_SPEC container: %s",
                                strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append_u16(req, IFLA_BRIDGE_FLAGS, br_flags);
        if (r < 0) {
                log_error_link(swport->link, "Could not append IFLA_BRIDGE_FLAGS attribute: %s",
                                strerror(-r));
                return r;
        }

        vinfo.vid= vlan_entry->vid;
        vinfo.flags = vlan_flags;

        r = sd_rtnl_message_append_binary(req, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof(vinfo));
        if (r < 0) {
                log_error_link(swport->link, "Could not append IFLA_BRIDGE_VLAN_INFO attribute: %s",
                                strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_link(swport->link, "Could not close container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call(swport->link->manager->rtnl, req, 0, NULL);
        if (r < 0) {
                log_error_link(swport->link, "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

    return 0;
}

static int swport_del_vlan(SWPort *swport, uint16_t vid) {
        int r;
        uint16_t br_flags = 0;
        struct bridge_vlan_info vinfo;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL;

        assert(swport);
        assert(swport->link);
        assert(swport->manager);
        assert(swport->manager->rtnl);

        r = sd_rtnl_message_new_vlan(swport->manager->rtnl, &req, RTM_DELLINK,
                        swport->link->ifindex);

        r = sd_rtnl_message_open_container(req, IFLA_AF_SPEC);
        if (r < 0) {
                log_error_link(swport->link, "Could not open IFLA_AF_SPEC container: %s",
                                strerror(-r));
                return r;
        }

        br_flags |= BRIDGE_FLAGS_SELF;

        r = sd_rtnl_message_append_u16(req, IFLA_BRIDGE_FLAGS, br_flags);
        if (r < 0) {
                log_error_link(swport->link, "Could not append IFLA_BRIDGE_FLAGS attribute: %s",
                                strerror(-r));
                return r;
        }
        vinfo.vid= vid;

        r = sd_rtnl_message_append_binary(req, IFLA_BRIDGE_VLAN_INFO, &vinfo, sizeof(vinfo));
        if (r < 0) {
                log_error_link(swport->link, "Could not append IFLA_BRIDGE_VLAN_INFO attribute: %s",
                                strerror(-r));
                return r;
        }

        r = sd_rtnl_message_close_container(req);
        if (r < 0) {
                log_error_link(swport->link, "Could not close container: %s", strerror(-r));
                return r;
        }

        r = sd_rtnl_call(swport->link->manager->rtnl, req, 0, NULL);
        if (r < 0) {
                log_error_link(swport->link, "Could not send rtnetlink message: %s", strerror(-r));
                return r;
        }

        return 0;
}

int config_parse_swattr(const char *unit,
        const char *filename,
        unsigned line,
        const char *section,
        unsigned section_line,
        const char *lvalue,
        int ltype,
        const char *rvalue,
        void *data,
        void *userdata) {
        int r;
        SWPortAttr *i = data;
        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = safe_atou64(rvalue,  &i->value);
        if (r == 0)
                i->flag = true;
        else
                i->flag = false;

        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                        "SwPortAttr is invalid, ignoring assignment: %s", rvalue);
                return 0;
        }

        return 0;
}

int config_parse_qos_attrs(const char *unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        SWPort* swport = userdata;
        SWPortQoSAttrs* attrs = NULL;
        SWPortQoSAttrs* attrs_tail = NULL;
        char ** a;
        int r;

        assert(filename);
        assert(userdata);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        attrs = new0(SWPortQoSAttrs, 1);
        if (!attrs)
                return log_oom();

        a = strv_split(rvalue, " ");
        if (a) {
                r = safe_atoi(a[0], &attrs->index);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                "QoSPortAttr is invalid, ignoring assignment: %s", rvalue);
                        return 0;
                }
                if (a[1]) {
                        r = safe_atou64(a[1], &attrs->value);
                        if (r < 0) {
                                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                        "QoSPortAttr is invalid, ignoring assignment: %s", rvalue);
                                return 0;
                        }
                }
                strv_free(a);
                attrs->ifla_attr = qosattr_ifla_from_string(lvalue);
                if ( attrs->ifla_attr < 0) {
                        log_error("Can not get IFLA attribute for %s", lvalue);
                        return 0;
                }

                LIST_FIND_TAIL(swport_qos_attrs, swport->qos_attrs, attrs_tail);
                LIST_INSERT_AFTER(swport_qos_attrs, swport->qos_attrs, attrs_tail, attrs);

        }

        return 0;
}

int config_parse_vlanid(const char *unit,
                          const char *filename,
                          unsigned line,
                          const char *section,
                          unsigned section_line,
                          const char *lvalue,
                          int ltype,
                          const char *rvalue,
                          void *data,
                          void *userdata) {
        SWPort *swport = userdata;
        _cleanup_vlanentry_free_ SWPortVlanEntry *vlan_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = vlan_entry_new(swport, section_line, &vlan_entry);
        if (r < 0) {
                log_error("Failed to allocate a new Vlan entry: %s", strerror(-r));
                return r;
        }

        r = config_parse_unsigned(unit, filename, line, section,
                                  section_line, lvalue, ltype,
                                  rvalue, &vlan_entry->vid, userdata);
        if (r < 0) {
                log_error("Failed to parse the VlanId value: %s", strerror(-r));
                return r;
        }

        vlan_entry = NULL;

        return 0;
}

int config_parse_untagged(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata)
{
         SWPort *swport = userdata;
        _cleanup_vlanentry_free_ SWPortVlanEntry *vlan_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = vlan_entry_new(swport, section_line, &vlan_entry);
        if (r < 0) {
                log_error("Failed to allocate a new Vlan entry: %s", strerror(-r));
                return r;
        }

        r = config_parse_bool(unit, filename, line, section,
                                  section_line, lvalue, ltype,
                                  rvalue, &vlan_entry->EgressUntagged, userdata);

        if (r < 0) {
                log_error("Failed to parse the EgressUntagged value: %s", strerror(-r));
                return r;
        }

        vlan_entry = NULL;

        return 0;
}
int config_parse_pvid(const char *unit,
                        const char *filename,
                        unsigned line,
                        const char *section,
                        unsigned section_line,
                        const char *lvalue,
                        int ltype,
                        const char *rvalue,
                        void *data,
                        void *userdata)
{
         SWPort *swport = userdata;
        _cleanup_vlanentry_free_ SWPortVlanEntry *vlan_entry = NULL;
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = vlan_entry_new(swport, section_line, &vlan_entry);
        if (r < 0) {
                log_error("Failed to allocate a new Vlan entry: %s", strerror(-r));
                return r;
        }

        r = config_parse_bool(unit, filename, line, section,
                                  section_line, lvalue, ltype,
                                  rvalue, &vlan_entry->pvid, userdata);

        if (r < 0) {
                log_error("Failed to parse the PVID value: %s", strerror(-r));
                return r;
        }

        vlan_entry = NULL;

        return 0;
}
