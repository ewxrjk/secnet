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
#include "util.h"

#define DEFAULT_SIZE 5
#define DEFAULT_MAXPRIV_BYTES 4095

struct ent {
    struct sigkeyid id;
    struct sigprivkey_if *sigpriv; /* 0 means none such */
};

struct privcache {
    closure_t cl;
    struct privcache_if ops;
    int used, alloc;
    struct pathprefix_template path;
    struct ent *ents;
    struct buffer_if databuf;
};

static bool_t uncached_load_file(
			   const struct sigscheme_info *scheme,
			   const char *path,
			   struct buffer_if *databuf,
			   struct sigprivkey_if **sigpriv_r,
			   closure_t **closure_r,
			   struct log_if *log);

static struct sigprivkey_if *uncached_get(struct privcache *st,
			   const struct sigkeyid *id, struct log_if *log)
{
    sprintf(st->path.write_here, SIGKEYID_PR_FMT, SIGKEYID_PR_VAL(id));

    const char *path=st->path.buffer;
    const struct sigscheme_info *scheme;
    for (scheme=sigschemes;
	 scheme->name;
	 scheme++)
	if (scheme->algid == id->b[GRPIDSZ])
	    goto found;

    slilog(log,M_ERR,"private key file %s not loaded (unknown algid)",
	   path);
    return 0;

 found:;
    struct sigprivkey_if *sigpriv;
    closure_t *cl;
    bool_t ok=uncached_load_file(scheme,
			      path,
			      &st->databuf,
			      &sigpriv,
			      &cl,
			      log);
    return ok ? sigpriv : 0;
}

static bool_t uncached_load_file(
			   const struct sigscheme_info *scheme,
			   const char *path,
			   struct buffer_if *databuf,
			   struct sigprivkey_if **sigpriv_r,
			   closure_t **closure_r,
			   struct log_if *log)
{
    bool_t ok=False;
    FILE *f=0;
    struct sigprivkey_if *sigpriv=0;

    f=fopen(path,"rb");
    if (!f) {
	if (errno == ENOENT) {
	    slilog(log,M_DEBUG,"private key %s not found",
		   path);
	} else {
	    slilog(log,M_ERR,"failed to open private key file %s",
		   path);
	}
	goto error_out;
    }

    setbuf(f,0);
    buffer_init(databuf,0);
    ssize_t got=fread(databuf->base,1,databuf->alloclen,f);
    if (ferror(f)) {
	slilog(log,M_ERR,"failed to read private-key file %s",
	       path);
	goto error_out;
    }
    if (!feof(f)) {
	slilog(log,M_ERR,"private key file %s longer than max %d",
	       path, (int)databuf->alloclen);
	goto error_out;
    }
    fclose(f); f=0;

    databuf->start=databuf->base;
    databuf->size=got;
    struct cloc loc = { .file=path, .line=0 };
    ok=scheme->loadpriv(scheme, databuf, &sigpriv, closure_r, log, loc);
    if (!ok) goto error_out; /* loadpriv will have logged */

    *sigpriv_r=sigpriv;

  out:
    if (f) fclose(f);
    return ok;

 error_out:
    if (sigpriv) sigpriv->dispose(sigpriv->st);
    ok=False;
    goto out;
}

static struct sigprivkey_if *privcache_lookup(void *sst,
					      const struct sigkeyid *id,
					      struct log_if *log) {
    struct privcache *st=sst;
    int was;
    struct ent result;

    for (was=0; was<st->used; was++) {
	if (sigkeyid_equal(id, &st->ents[was].id)) {
	    result = st->ents[was];
	    goto found;
	}
    }

    if (st->used < st->alloc) {
	was=st->used;
	st->used++;
    } else {
	was=st->used-1;
	if (st->ents[was].sigpriv) {
	    st->ents[was].sigpriv->dispose(st->ents[was].sigpriv->st);
	}
    }

    COPY_OBJ(result.id, *id);
    result.sigpriv=uncached_get(st,id,log);

 found:
    memmove(&st->ents[1], &st->ents[0], sizeof(st->ents[0]) * was);
    st->ents[0]=result;
    return result.sigpriv;
}

static list_t *privcache_apply(closure_t *self, struct cloc loc,
			       dict_t *context, list_t *args)
{
    struct privcache *st;
    item_t *item;
    dict_t *dict;

    NEW(st);
    st->cl.description="privcache";
    st->cl.type=CL_PRIVCACHE;
    st->cl.apply=NULL;
    st->cl.interface=&st->ops;
    st->ops.st=st;
    st->ops.lookup=privcache_lookup;
    st->ents=0;
    st->path.buffer=0;
    st->used=st->alloc=0;

    item=list_elem(args,0);
    if (!item || item->type!=t_dict)
	cfgfatal(loc,"privcache","parameter must be a dictionary\n");
    
    dict=item->data.dict;

    st->alloc=dict_read_number(dict,"privcache-size",False,"privcache",loc,
			       DEFAULT_SIZE);
    NEW_ARY(st->ents,st->alloc);
    st->used=0;

    int32_t buflen=dict_read_number(dict,"privkey-max",False,"privcache",loc,
				    DEFAULT_MAXPRIV_BYTES);
    buffer_new(&st->databuf,buflen+1);

    const char *path=dict_read_string(dict,"privkeys",True,"privcache",loc);
    pathprefix_template_init(&st->path,path,KEYIDSZ*2);

    return new_closure(&st->cl);
}

static list_t *loadprivate_apply(closure_t *self, struct cloc loc,
			       dict_t *context, list_t *args)
{
    CL_GET_STR_ARG(0,algname,"algorithm name");
    CL_GET_STR_ARG(1,path,"private key path");

    const struct sigscheme_info *sch=sigscheme_lookup(algname);
    if (!sch) cfgfatal(algname_i->loc,"load-private",
		       "unknown algorithm `%s'",algname);

    struct buffer_if databuf;
    buffer_new(&databuf,DEFAULT_MAXPRIV_BYTES);
    BUF_ALLOC(&databuf,"load-private data buf");

    struct cfgfile_log log;
    cfgfile_log_init(&log,loc,"load-private");

    struct sigprivkey_if *sigpriv;
    closure_t *cl;
    bool_t ok=
	uncached_load_file(sch,path,&databuf,&sigpriv,&cl,&log.log);
    if (!ok) cfgfatal(loc,"load-private","private key loading failed");

    BUF_FREE(&databuf);
    buffer_destroy(&databuf);
    return new_closure(cl);
}

void privcache_module(dict_t *dict)
{
    add_closure(dict,"priv-cache",privcache_apply);
    add_closure(dict,"load-private",loadprivate_apply);
}
