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
static bool_t random_generate(void *data, int32_t bytes, uint8_t *buff)
{
    struct rgen_data *st=data;
    int r;

    r= read(st->fd,buff,bytes);

    assert(r == bytes);
    /* This is totally crap error checking, but AFAICT many callers of
     * this function do not check the return value.  This is a minimal
     * change to make the code not fail silently-but-insecurely.
     *
     * A proper fix requires either:
     *  - Declare all random number generation failures as fatal
     *    errors, and make this return void, and fix all callers,
     *    and make this call some appropriate function if it fails.
     *  - Make this have proper error checking (and reporting!)
     *    and make all callers check the error (and report!);
     *    this will be tricky, I think, because you have to report
     *    the errno somewhere.
     *
     * There's also the issue that this is only one possible
     * implementation of a random number source; others may not rely
     * on reading from a file descriptor, and may not produce
     * appropriate settings of errno.
     */

    return True;
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
