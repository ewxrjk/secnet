/*
 * This file is part of secnet.
 * See README for full list of copyright holders.
 *
 * secnet is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * secnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * version 3 along with secnet; if not, see
 * https://www.gnu.org/licenses/gpl.html.
 */

#include "secnet.h"

void init_builtin_modules(dict_t *dict)
{
    resolver_module(dict);
    random_module(dict);
    udp_module(dict);
    polypath_module(dict);
    util_module(dict);
    site_module(dict);
    transform_eax_module(dict);
    transform_cbcmac_module(dict);
    netlink_module(dict);
    rsa_module(dict);
    dh_module(dict);
    md5_module(dict);
    slip_module(dict);
    tun_module(dict);
    sha1_module(dict);
    log_module(dict);
}

const struct sigscheme_info sigschemes[]={
    { 0 }
};
