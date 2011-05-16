#include "secnet.h"

void init_builtin_modules(dict_t *dict)
{
    resolver_module(dict);
    random_module(dict);
    udp_module(dict);
    util_module(dict);
    site_module(dict);
    transform_module(dict);
    netlink_module(dict);
    rsa_module(dict);
    dh_module(dict);
    md5_module(dict);
    slip_module(dict);
    tun_module(dict);
    sha1_module(dict);
    log_module(dict);
}
