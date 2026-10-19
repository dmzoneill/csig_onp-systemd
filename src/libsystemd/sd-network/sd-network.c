/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright 2011 Lennart Poettering
 * Copyright 2014 Tom Gundersen
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/poll.h>
#include <net/if.h>

#include "util.h"
#include "macro.h"
#include "strv.h"
#include "fileio.h"
#include "sd-network.h"
#include "network-internal.h"

static int network_parse_string(const char *path, const char *key, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        assert(path);
        assert(key);
        assert_return(ret, -EINVAL);

        r = parse_env_file(path, NEWLINE, key, &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s))
                return -ENODATA;

        *ret = s;
        s = NULL;

        return 0;
}

static int network_parse_link_string(int ifindex, const char *key, char **ret) {
        _cleanup_free_ char *p = NULL;

        assert_return(ifindex > 0, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        return network_parse_string(p, key, ret);
}

static int network_parse_strv(const char *path, const char *key, char ***ret) {
        _cleanup_strv_free_ char **a = NULL;
        _cleanup_free_ char *s = NULL;
        int r;

        assert(path);
        assert(key);
        assert_return(ret, -EINVAL);

        r = parse_env_file(path, NEWLINE, key, &s, NULL);
        if (r == -ENOENT)
                return -ENODATA;
        if (r < 0)
                return r;
        if (isempty(s)) {
                *ret = NULL;
                return 0;
        }

        a = strv_split(s, " ");
        if (!a)
                return -ENOMEM;

        strv_uniq(a);
        r = strv_length(a);

        *ret = a;
        a = NULL;

        return r;
}

static int network_parse_link_strv(int ifindex, const char *key, char ***ret) {
        _cleanup_free_ char *p = NULL;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/links/%d", ifindex) < 0)
                return -ENOMEM;

        return network_parse_strv(p, key, ret);
}

static int network_parse_ufd_string(int group_id, const char *key, char **ret) {
        _cleanup_free_ char *p = NULL;

        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/ufd/groups/%d", group_id) < 0)
                return -ENOMEM;

        return network_parse_string(p, key, ret);
}

static int network_parse_ufd_strv(int group_id, const char *key, char ***ret) {
        _cleanup_free_ char *p = NULL;

        assert_return(ret, -EINVAL);

        if (asprintf(&p, "/run/systemd/netif/ufd/groups/%d", group_id) < 0)
                return -ENOMEM;

        return network_parse_strv(p, key, ret);
}

_public_ int sd_network_get_operational_state(char **state) {
        assert_return(state, -EINVAL);

        return network_parse_string("/run/systemd/netif/state", "OPER_STATE", state);
}

_public_ int sd_network_get_dns(char ***ret) {
        return network_parse_strv("/run/systemd/netif/state", "DNS", ret);
}

_public_ int sd_network_get_ntp(char ***ret) {
        return network_parse_strv("/run/systemd/netif/state", "NTP", ret);
}

_public_ int sd_network_get_domains(char ***ret) {
        return network_parse_strv("/run/systemd/netif/state", "DOMAINS", ret);
}

_public_ int sd_network_link_get_setup_state(int ifindex, char **state) {
        assert_return(state, -EINVAL);

        return network_parse_link_string(ifindex, "ADMIN_STATE", state);
}

_public_ int sd_network_link_get_network_file(int ifindex, char **filename) {
        assert_return(filename, -EINVAL);

        return network_parse_link_string(ifindex, "NETWORK_FILE", filename);
}

_public_ int sd_network_link_get_operational_state(int ifindex, char **state) {
        assert_return(state, -EINVAL);

        return network_parse_link_string(ifindex, "OPER_STATE", state);
}

_public_ int sd_network_link_get_llmnr(int ifindex, char **llmnr) {
        assert_return(llmnr, -EINVAL);

        return network_parse_link_string(ifindex, "LLMNR", llmnr);
}

_public_ int sd_network_link_get_dns(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "DNS", ret);
}

_public_ int sd_network_link_get_ntp(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "NTP", ret);
}

_public_ int sd_network_link_get_domains(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "DOMAINS", ret);
}

_public_ int sd_network_link_get_carrier_bound_to(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "CARRIER_BOUND_TO", ret);
}

_public_ int sd_network_link_get_carrier_bound_by(int ifindex, char ***ret) {
        return network_parse_link_strv(ifindex, "CARRIER_BOUND_BY", ret);
}

_public_ int sd_network_link_get_wildcard_domain(int ifindex) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = network_parse_link_string(ifindex, "WILDCARD_DOMAIN", &s);
        if (r < 0)
                return r;

        return parse_boolean(s);
}

static inline int MONITOR_TO_FD(sd_network_monitor *m) {
        return (int) (unsigned long) m - 1;
}

static inline sd_network_monitor* FD_TO_MONITOR(int fd) {
        return (sd_network_monitor*) (unsigned long) (fd + 1);
}

_public_ int sd_network_monitor_new(sd_network_monitor **m, const char *category) {
        int fd, k;
        bool good = false;

        assert_return(m, -EINVAL);

        fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!category || streq(category, "links")) {
                k = inotify_add_watch(fd, "/run/systemd/netif/links/", IN_MOVED_TO|IN_DELETE);
                if (k < 0) {
                        safe_close(fd);
                        return -errno;
                }

                good = true;
        }

        if (!good) {
                close_nointr(fd);
                return -EINVAL;
        }

        *m = FD_TO_MONITOR(fd);
        return 0;
}

_public_ sd_network_monitor* sd_network_monitor_unref(sd_network_monitor *m) {
        int fd;

        assert_return(m, NULL);

        fd = MONITOR_TO_FD(m);
        close_nointr(fd);

        return NULL;
}

_public_ int sd_network_monitor_flush(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        return flush_fd(MONITOR_TO_FD(m));
}

_public_ int sd_network_monitor_get_fd(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        return MONITOR_TO_FD(m);
}

_public_ int sd_network_monitor_get_events(sd_network_monitor *m) {

        assert_return(m, -EINVAL);

        /* For now we will only return POLLIN here, since we don't
         * need anything else ever for inotify.  However, let's have
         * this API to keep our options open should we later on need
         * it. */
        return POLLIN;
}

_public_ int sd_network_monitor_get_timeout(sd_network_monitor *m, uint64_t *timeout_usec) {

        assert_return(m, -EINVAL);
        assert_return(timeout_usec, -EINVAL);

        /* For now we will only return (uint64_t) -1, since we don't
         * need any timeout. However, let's have this API to keep our
         * options open should we later on need it. */
        *timeout_usec = (uint64_t) -1;
        return 0;
}

_public_ int sd_network_ufd_get_setup_state(int group_id, char **state) {
        assert_return(state, -EINVAL);

        return network_parse_ufd_string(group_id, "GROUP_STATE", state);
}

_public_ int sd_network_ufd_get_config_file(int group_id, char **filename) {
        assert_return(filename, -EINVAL);

        return network_parse_ufd_string(group_id, "CONFIG_FILE", filename);
}

_public_ int sd_network_ufd_get_uplinks(int group_id, char ***ret) {
        return network_parse_ufd_strv(group_id, "UPLINKS", ret);
}

_public_ int sd_network_ufd_get_downlinks(int group_id, char ***ret) {
        return network_parse_ufd_strv(group_id, "DOWNLINKS", ret);
}

_public_ int sd_network_ufd_get_group_list(char ***ret) {
        int r;

        r = network_parse_strv("/run/systemd/netif/ufd/state", "GROUP_LIST", ret);
        if (r < 0)
                return r;

        return 0;
}
