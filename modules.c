#include "config.h"
#include "secnet.h"

extern init_module resolver_module;
extern init_module random_module;
extern init_module udp_module;
extern init_module util_module;
extern init_module site_module;
extern init_module transform_module;
extern init_module netlink_module;
extern init_module rsa_module;
extern init_module dh_module;
extern init_module md5_module;

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
}
