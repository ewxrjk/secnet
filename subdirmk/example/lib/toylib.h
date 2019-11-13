/*
 * subdirmk - example code
 *  Copyright 2019 Mark Wooding
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef LIBTOY_H
#define LIBTOY_H

#include <string.h>

#define STRCMP(x, op, y) (strcmp((x), (y)) op 0)
#define STRNCMP(x, op, y, n) (strncmp((x), (y), (n)) op 0)
#define MEMCMP(x, op, y, n) (memcmp((x), (y), (n)) op 0)

extern const char *greeting(void);

#endif
