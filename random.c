#include "secnet.h"
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct rgen_data {
    closure_t cl;
    struct random_if ops;
    struct cloc loc;
    int fd;
};

static random_fn random_generate;
static bool_t random_generate(void *data, uint32_t bytes, uint8_t *buff)
{
    struct rgen_data *st=data;

    /* XXX XXX error checking */
    read(st->fd,buff,bytes);

    return True;
}

static list_t *random_apply(closure_t *self, struct cloc loc,
			    dict_t *context, list_t *args)
{
    struct rgen_data *st;
    item_t *arg1, *arg2;
    string_t filename=NULL;

    st=safe_malloc(sizeof(*st),"random_apply");

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
	fatal("randomsource: requires a filename\n");
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
	fatal("randomsource requires a filename");
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
