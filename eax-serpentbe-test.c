/*
 * This file is part of secnet.
 * See LICENCE and this file CREDITS for full list of copyright holders.
 * SPDX-License-Identifier: GPL-3.0-or-later
 * There is NO WARRANTY.
 */

#include "eax-test.h"
#include "serpent.h"
/* multiple-inclusion protection means that serpent.h's inclusion
 * by eax-serpent-test.c is suppressed, so we don't get useless
 * duplicate declarations of serpentbe_makekey and serpentbe_encrypt
 */
#define serpent_makekey serpentbe_makekey
#define serpent_encrypt serpentbe_encrypt
#include "eax-serpent-test.c"
