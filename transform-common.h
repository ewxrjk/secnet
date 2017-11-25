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

#ifndef TRANSFORM_COMMON_H
#define TRANSFORM_COMMON_H

#include "magic.h"

#define KEYED_CHECK do{				\
	if (!ti->keyed) {			\
	    *errmsg="transform unkeyed";	\
	    return 1;				\
	}					\
    }while(0)

#define RECVBITMAP_SIZE 32
typedef uint32_t recvbitmap_type;

#define SEQNUM_CHECK(seqnum, p) do{				\
	uint32_t skew=seqnum-ti->lastrecvseq;			\
	if (skew<0x8fffffff) {					\
	    /* Ok */						\
	    ti->lastrecvseq=seqnum;				\
	    if (skew < RECVBITMAP_SIZE)				\
                ti->recvbitmap <<= skew;			\
            else						\
                ti->recvbitmap=0;				\
            skew=0;						\
	} else if ((0-skew)<(p)->max_seq_skew) {		\
	    /* Ok */						\
	} else {						\
	    /* Too much skew */					\
	    *errmsg="seqnum: too much skew";			\
	    return 2;						\
	}							\
	if ((p)->dedupe) {					\
	    recvbitmap_type recvbit=(uint32_t)1 << skew;	\
	    if (ti->recvbitmap & recvbit) {			\
		*errmsg="seqnum: duplicate";			\
		return 2;					\
	    }							\
	    ti->recvbitmap |= recvbit;				\
	}							\
    }while(0)

#define SEQNUM_KEYED_FIELDS						\
    uint32_t sendseq;							\
    uint32_t lastrecvseq;						\
    recvbitmap_type recvbitmap; /* 1<<0 is lastrecvseq (i.e., most recent) */ \
    bool_t keyed

#define SEQNUM_KEYED_INIT(initlastrecvseq,initsendseq)	\
    (ti->lastrecvseq=(initlastrecvseq),			\
     ti->sendseq=(initsendseq),				\
     ti->recvbitmap=0,					\
     ti->keyed=True)

#define TRANSFORM_VALID				\
    static bool_t transform_valid(void *sst)	\
    {						\
	struct transform_inst *ti=sst;		\
						\
	return ti->keyed;			\
    }

#define TRANSFORM_DESTROY				\
    static void transform_destroy(void *sst)		\
    {							\
	struct transform_inst *st=sst;			\
							\
	FILLZERO(*st); /* Destroy key material */	\
	free(st);					\
    }

#define SET_CAPAB_TRANSFORMNUM(def) do{					\
        st->ops.capab_transformnum=dict_read_number(dict, "capab-num",	\
                                     False, "transform", loc, (def));	\
        if (st->ops.capab_transformnum > CAPAB_TRANSFORMNUM_MAX)	\
	    cfgfatal(loc,"transform","capab-num out of range 0..%d\n",	\
		     CAPAB_TRANSFORMNUM_MAX);				\
    }while(0)

#define TRANSFORM_CREATE_CORE				\
	struct transform_inst *ti;			\
	NEW(ti);					\
	/* mlock XXX */					\
	ti->ops.st=ti;					\
	ti->ops.setkey=transform_setkey;		\
	ti->ops.valid=transform_valid;			\
	ti->ops.delkey=transform_delkey;		\
	ti->ops.forwards=transform_forward;		\
	ti->ops.reverse=transform_reverse;		\
	ti->ops.destroy=transform_destroy;		\
	ti->keyed=False;

#define SEQNUM_PARAMS_FIELDS			\
    uint32_t max_seq_skew;			\
    bool_t dedupe;

#define SEQNUM_PARAMS_INIT(dict,p,desc,loc)				\
    (p)->max_seq_skew=dict_read_number((dict), "max-sequence-skew",	\
					False, (desc), (loc), 10);	\
    bool_t can_dedupe=(p)->max_seq_skew < RECVBITMAP_SIZE;		\
    (p)->dedupe=dict_read_bool((dict), "dedupe",			\
			       False,(desc),(loc), can_dedupe);		\
    if ((p)->dedupe && !can_dedupe)					\
	cfgfatal(loc,"transform",					\
                 "cannot dedupe with max-sequence-skew>=32");		\
    else (void)0

#endif /*TRANSFORM_COMMON_H*/
