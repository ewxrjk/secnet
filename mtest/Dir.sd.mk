# This file is part of secnet.
# See LICENCE and this file CREDITS for full list of copyright holders.
# SPDX-License-Identifier: GPL-3.0-or-later
# There is NO WARRANTY.

&DEPS += &~/make-secnet-sites
&DEPS += &~/ipaddrset.py
&DEPS += &^/common.tcl

&:include test-common.sd.mk

&check:: &check-real
