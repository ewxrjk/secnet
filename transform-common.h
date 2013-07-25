
#ifndef TRANSFORM_COMMON_H
#define TRANSFORM_COMMON_H

#define KEYED_CHECK do{				\
	if (!ti->keyed) {			\
	    *errmsg="transform unkeyed";	\
	    return 1;				\
	}					\
    }while(0)

#define SEQNUM_CHECK(seqnum, max_skew) do{	\
	uint32_t skew=seqnum-ti->lastrecvseq;	\
	if (skew<0x8fffffff) {			\
	    /* Ok */				\
	    ti->lastrecvseq=seqnum;		\
	} else if ((0-skew)<max_skew) {	\
	    /* Ok */				\
	} else {				\
	    /* Too much skew */			\
	    *errmsg="seqnum: too much skew";	\
	    return 2;				\
	}					\
    }while(0)

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

#define TRANSFORM_CREATE_CORE				\
	struct transform_inst *ti;			\
	ti=safe_malloc(sizeof(*ti),"transform_create");	\
	/* mlock XXX */					\
	ti->ops.st=ti;					\
	ti->ops.setkey=transform_setkey;		\
	ti->ops.valid=transform_valid;			\
	ti->ops.delkey=transform_delkey;		\
	ti->ops.forwards=transform_forward;		\
	ti->ops.reverse=transform_reverse;		\
	ti->ops.destroy=transform_destroy;		\
	ti->ops.max_start_pad=st->ops.max_start_pad;	\
	ti->keyed=False;

#endif /*TRANSFORM_COMMON_H*/
