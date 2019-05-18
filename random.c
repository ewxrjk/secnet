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
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

struct rgen_data {
    closure_t cl;
    struct random_if ops;
    struct cloc loc;
    int fd;
};

static random_fn random_generate;
static void random_generate(void *data, int32_t bytes, uint8_t *buff)
{
    struct rgen_data *st=data;
    int r;

    r= read(st->fd,buff,bytes);

    assert(r == bytes);
    /* This is totally crap error checking, but callers of
     * this function do not check the return value and dealing
     * with failure of this everywhere would be very inconvenient.
     */
}

static list_t *random_apply(closure_t *self, struct cloc loc,
			    dict_t *context, list_t *args)
{
    struct rgen_data *st;
    item_t *arg1, *arg2;
    string_t filename=NULL;

    NEW(st);

    st->cl.description="randomsource";
    st->cl.type=CL_RANDOMSRC;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.blocking=False;
    st->ops.generate=random_generate;
    st->loc=loc;

    arg1=list_elem(args,0);
    arg2=list_elem(args,1);

    if (!arg1) {
	cfgfatal(loc,"randomsource","requires a filename\n");
    }
    if (arg1->type != t_string) {
	cfgfatal(arg1->loc,"randomsource",
		 "filename (arg1) must be a string\n");
    }
    filename=arg1->data.string;

    if (arg2) {
	if (arg2->type != t_bool) {
	    cfgfatal(arg2->loc,"randomsource",
		     "blocking parameter (arg2) must be bool\n");
	}
	st->ops.blocking=arg2->data.bool;
    }

    if (!filename) {
	cfgfatal(loc,"randomsource","requires a filename\n");
    }
    st->fd=open(filename,O_RDONLY);
    if (st->fd<0) {
	fatal_perror("randomsource (%s:%d): cannot open %s",arg1->loc.file,
		     arg1->loc.line,filename);
    }
    return new_closure(&st->cl);
}

void random_module(dict_t *d)
{
    add_closure(d,"randomfile",random_apply);
}
