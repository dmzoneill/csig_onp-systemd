/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright (C) 2014 Intel Corporation. All rights reserved.
 */

#pragma once

typedef struct Team Team;

#include "networkd-netdev.h"

struct Team {
        NetDev meta;
};

extern const NetDevVTable team_vtable;

int netdev_team_delete_not_configured(Manager *manager);
