/*
 * $Log$
 */

/* conffile.c - process the configuration file */

/* #define DUMP_PARSE_TREE */

#include "secnet.h"
#include <stdio.h>
#include <string.h>
#include "conffile.h"
#include "conffile_internal.h"
#include "util.h"
#include "modules.h"

static struct cloc no_loc={"none",0};

struct atomlist {
    struct atomlist *next;
    atom_t a;
};

struct entry {
    struct entry *next;
    atom_t key;
    list_t *val;
};

struct searchlist {
    struct dict *d;
    struct searchlist *next;
};

struct dict {
    struct dict *parent;
    struct searchlist *search;
    struct entry *entries;
    uint32_t size;
};

static struct atomlist *atoms=NULL;

static void process_alist(dict_t *context, struct p_node *c);
static list_t *process_invocation(dict_t *context, struct p_node *i);

static list_t *dict_ilookup_primitive(dict_t *dict, atom_t key)
{
    struct entry *i;
    for (i=dict->entries; i; i=i->next) {
	if (key==i->key) return i->val;
    }
    return NULL;
}

static list_t *dict_ilookup(dict_t *dict, atom_t key)
{
    dict_t *d;
    list_t *v;

    v=dict_ilookup_primitive(dict, key);
    if (v) return v;
    /* Check dictionaries in search path */
/* XXX */
    /* Check lexical parents */
    for (d=dict; d; d=d->parent) {
	v=dict_ilookup_primitive(d, key);
	if (v) return v;
    }
    return NULL;
}

static void dict_iadd(dict_t *dict, atom_t key, list_t *val)
{
    struct entry *e;
    /* XXX May want to permit redefinition of keys in the future */
    /* (although it could be very confusing) */
    if (dict_ilookup_primitive(dict, key)) {
	fatal("duplicate key \"%s\" in dictionary\n",key);
    }
    e=safe_malloc(sizeof(*e),"dict_add");
    e->next=dict->entries;
    e->key=key;
    e->val=val;
    dict->entries=e;
    dict->size++;
}

/***** Functions beyond this point are private to the config system *****/

static dict_t *dict_new(dict_t *parent)
{
    dict_t *d;

    d=safe_malloc(sizeof(*d),"dict_new");
    d->parent=parent;
    d->search=NULL;
    d->entries=NULL;
    d->size=0;
    return d;
}

static struct p_node *node_copy(struct p_node *n)
{
    struct p_node *r;
    r=safe_malloc(sizeof(*r),"node_copy");
    *r=*n;
    return r;
}

static struct p_node *list_reverse(struct p_node *list)
{
    struct p_node *rl=NULL, *i, *n;

    for (i=list; i; i=i->r) {
	n=node_copy(i);
	n->r=rl;
	rl=n;
    }
    return rl;
}

/* Since we use left-recursion in the parser for efficiency, sequences
   end up "backwards" in the parse tree. Rather than have complicated
   code for, eg. processing assignments in the right order, we reverse
   these sequences here. */
static void ptree_mangle(struct p_node *t)
{
    if (!t) return;
    ptree_mangle(t->l);
    ptree_mangle(t->r);
    switch (t->type) {
    case T_DICT:
	/* ASSERT !t->l || t->l->type==T_ALIST */
	/* ASSERT !t->r || t->r->type==T_LISTITEM */
	t->l=list_reverse(t->l);
	t->r=list_reverse(t->r);
	break;
    case T_ASSIGNMENT:
	/* ASSERT t->l->type==T_KEY */
	/* ASSERT t->r->type==T_LISTITEM */
	t->r=list_reverse(t->r);
	break;
    case T_ABSPATH:
    case T_RELPATH:
	/* ASSERT t->l==NULL */
	/* ASSERT t->r->type==T_PATHELEM */
	t->r=list_reverse(t->r);
	break;
    case T_EXEC:
	/* ASSERT t->l */
	/* ASSERT t->r->type==T_LISTITEM */
	t->r=list_reverse(t->r);
	break;
    }
}

#ifdef DUMP_PARSE_TREE
/* Convert a node type to a string, for parse tree dump */
static string_t ntype(uint32_t type)
{
    switch(type) {
    case T_STRING:     return "T_STRING";
    case T_NUMBER:     return "T_NUMBER";
    case T_KEY:        return "T_KEY";
    case T_ASSIGNMENT: return "T_ASSIGNMENT";
    case T_LISTITEM:   return "T_LISTITEM";
    case T_EXEC:       return "T_EXEC";
    case T_PATHELEM:   return "T_PATHELEM";
    case T_ABSPATH:    return "T_ABSPATH";
    case T_RELPATH:    return "T_RELPATH";
    case T_DICT:       return "T_DICT";
    case T_ALIST:      return "T_ALIST";
    case T_ERROR:      return "T_ERROR";
    }
    return "**unknown**";
}

static void ptree_indent(uint32_t amount)
{
    uint32_t i;
    for (i=0; i<amount; i++) printf("  . ");
}

static void ptree_dump(struct p_node *n, uint32_t d)
{
    if (!n) {
	printf("NULL\n");
	return;
    }
    
    if (n->type<10) {
	switch(n->type) {
	case T_STRING: printf("T_STRING: \"%s\" (%s line %d)\n",
			      n->data.string,n->loc.file,n->loc.line); break;
	case T_NUMBER: printf("T_NUMBER: %d (%s line %d)\n",
			      n->data.number, n->loc.file,n->loc.line);	break;
	case T_KEY:    printf("T_KEY:    %s (%s line %d)\n",
			      n->data.key, n->loc.file,n->loc.line); break;
	default:       printf("**unknown primitive type**\n"); break;
	}
    } else {
	printf("%s: (%s line %d)\n",ntype(n->type),n->loc.file,n->loc.line);
	ptree_indent(d);
	printf("  |-");	ptree_dump(n->l, d+1);
	ptree_indent(d);
	printf("  +-"); ptree_dump(n->r, d+1);
    }
}

#endif /* DUMP_PARSE_TREE */

static dict_t *dict_find_root(dict_t *d)
{
    dict_t *i;

    for (i=d; i->parent; i=i->parent);
    return i;
}

static list_t *dict_lookup_path(dict_t *context, struct p_node *p)
{
    dict_t *i;
    list_t *l;

    /* ASSERT p->type==T_PATHELEM */
    /* ASSERT p->l->type==T_KEY */
    l=dict_ilookup(context, p->l->data.key);
    if (!l) {
	cfgfatal(p->loc,"conffile","can't find key %s\n",
		 p->l->data.key);
    }

    while (p->r) {
	if (l->item->type != t_dict) {
	    cfgfatal(p->loc,"conffile","path element \"%s\" "
		     "is not a dictionary\n",p->l->data.key);
	}
	i=l->item->data.dict; /* First thing in list */

	p=p->r;
	l=dict_ilookup_primitive(i, p->l->data.key);
	if (!l) {
	    cfgfatal(p->loc,"conffile","can't find key %s\n",
		     p->l->data.key);
	}
    }
    return l;
}

static item_t *new_item(enum types type, struct cloc loc)
{
    item_t *i;

    i=safe_malloc(sizeof(*i),"new_item");
    i->type=type;
    i->loc=loc;
    return i;
}

static list_t *process_item(dict_t *context, struct p_node *i)
{
    item_t *item=NULL;

    switch (i->type) {
    case T_STRING:
	item=new_item(t_string, i->loc);
	item->data.string=i->data.string; /* XXX maybe strcpy */
	break;
    case T_NUMBER:
	item=new_item(t_number, i->loc);
	item->data.number=i->data.number;
	break;
    case T_ABSPATH:
	context=dict_find_root(context);
	/* falls through */
    case T_RELPATH:
	return dict_lookup_path(context, i->r);
	/* returns immediately */
	break;
    case T_DICT:
	item=new_item(t_dict, i->loc);
	item->data.dict=dict_new(context);
/* XXX	dict_add_searchpath(context,process_ilist(context, i->r)); */
	process_alist(item->data.dict, i->l);
	break;
    case T_EXEC:
	return process_invocation(context, i);
	/* returns immediately */
	break;
    default:
#ifdef DUMP_PARSE_TREE
	ptree_dump(i,0);
	fatal("process_item: invalid node type for a list item (%s)\n",
	      ntype(i->type));
#else
	fatal("process_item: list item has invalid node type %d - recompile "
	      "with DUMP_PARSE_TREE defined in conffile.c for more "
	      "detailed debug output",i->type);
#endif /* DUMP_PARSE_TREE */
	break;
    }
    return list_append(NULL,item);
}

static list_t *process_ilist(dict_t *context, struct p_node *l)
{
    struct p_node *i;
    list_t *r;

    /* ASSERT l->type==T_LISTITEM */

    r=list_new();

    for (i=l; i; i=i->r) {
	r=list_append_list(r,process_item(context,i->l));
    }
    return r;
}
	
static list_t *process_invocation(dict_t *context, struct p_node *i)
{
    list_t *cll;
    item_t *cl;
    list_t *args;

    /* ASSERT i->type==T_EXEC */
    /* ASSERT i->r->type==T_LISTITEM */
    /* XXX it might be null too */
    cll=process_item(context,i->l);
    cl=cll->item;
    if (cl->type != t_closure) {
	cfgfatal(i->l->loc,"conffile","only closures can be invoked\n");
    }
    args=process_ilist(context, i->r);
    return cl->data.closure->apply(cl->data.closure, i->loc, context, args);
}

static void process_alist(dict_t *context, struct p_node *c)
{
    struct p_node *i;
    atom_t k;
    list_t *l;

    if (!c) return; /* NULL assignment lists are valid (empty dictionary) */

    /* ASSERT c->type==T_ALIST */
    if (c->type!=T_ALIST) {
	fatal("invalid node type in assignment list\n");
    }

    for (i=c; i; i=i->r) {
	/* ASSERT i->l && i->l->type==T_ASSIGNMENT */
	/* ASSERT i->l->l->type==T_KEY */
	/* ASSERT i->l->r->type==T_LISTITEM */
	k=i->l->l->data.key;
	l=process_ilist(context, i->l->r);
	dict_iadd(context, k, l);
    }
}

/* Take a list of items; turn any dictionaries in this list into lists */
static list_t *makelist(closure_t *self, struct cloc loc,
			dict_t *context, list_t *args)
{
    list_t *r=NULL, *i;
    struct entry *e;
    
    for (i=args; i; i=i->next) {
	if (i->item->type==t_dict) {
	    /* Convert */
	    for (e=i->item->data.dict->entries; e; e=e->next) {
		r=list_append_list(r, e->val);
	    }
	} else {
	    r=list_append_list(r, list_append(NULL,i->item));
	}
    }
    return r;
}

/* Take a list consisting of a closure and some other things. Apply the
   closure to the other things, and return the resulting list */
static list_t *map(closure_t *self, struct cloc loc, dict_t *context,
		   list_t *args)
{
    list_t *r=NULL, *al;
    item_t *ci;
    closure_t *cl;
    list_t se;
    
    ci=list_elem(args,0);
    if (ci && ci->type==t_closure) {
	cl=ci->data.closure;
	if (!cl->apply) {
	    cfgfatal(loc,"map","closure cannot be applied\n");
	}
	for (al=args->next; al; al=al->next) {
	    /* Construct a single-element list */
	    se.next=NULL;
	    se.item=al->item;
	    /* Invoke the closure, append its result to the output */
	    r=list_append_list(r,cl->apply(cl,loc,context,&se));
	}
    } else {
	cfgfatal(loc,"map","you must supply a closure as the "
		 "first argument\n");
    }
    return r;
}

/* Read a file and turn it into a string */
static list_t *readfile(closure_t *self, struct cloc loc,
			dict_t *context, list_t *args)
{
    FILE *f;
    string_t filename;
    long length;
    item_t *r;

    r=list_elem(args,0);
    if (!r) {
	cfgfatal(loc,"readfile","you must supply a filename\n");
    }
    if (r->type!=t_string) {
	cfgfatal(loc,"readfile","filename must be a string\n");
    }
    filename=r->data.string;
    f=fopen(filename,"rb");
    if (!f) {
	fatal_perror("readfile (%s:%d): cannot open file \"%s\"",
		     loc.file,loc.line, filename);
    }
    if (fseek(f, 0, SEEK_END)!=0) {
	fatal_perror("readfile (%s:%d): fseek(SEEK_END)",loc.file,loc.line);
    }
    length=ftell(f);
    if (length<0) {
	fatal_perror("readfile (%s:%d): ftell()",loc.file,loc.line);
    }
    if (fseek(f, 0, SEEK_SET)!=0) {
	fatal_perror("readfile (%s:%d): fseek(SEEK_SET)",loc.file,loc.line);
    }
    r=new_item(t_string,loc);
    r->data.string=safe_malloc(length+1,"readfile");
    if (fread(r->data.string,length,1,f)!=1) {
	fatal("readfile (%s:%d): fread: could not read all of file\n",
	      loc.file,loc.line);
    }
    r->data.string[length]=0;
    if (fclose(f)!=0) {
	fatal_perror("readfile (%s:%d): fclose",loc.file,loc.line);
    }
    return list_append(NULL,r);
}
    
static dict_t *process_config(struct p_node *c)
{
    dict_t *root;
    dict_t *context;
    item_t *i;
    list_t *false;
    list_t *true;

    root=dict_new(NULL);
    context=root;

    /* Predefined keys for boolean values */
    i=new_item(t_bool,no_loc);
    i->data.bool=False;
    false=list_append(NULL,i);
    i=new_item(t_bool,no_loc);
    i->data.bool=True;
    true=list_append(NULL,i);
    dict_add(root,"false",false);
    dict_add(root,"False",false);
    dict_add(root,"FALSE",false);
    dict_add(root,"no",false);
    dict_add(root,"No",false);
    dict_add(root,"NO",false);
    dict_add(root,"true",true);
    dict_add(root,"True",true);
    dict_add(root,"TRUE",true);
    dict_add(root,"yes",true);
    dict_add(root,"Yes",true);
    dict_add(root,"YES",true);

    add_closure(root,"makelist",makelist);
    add_closure(root,"readfile",readfile);
    add_closure(root,"map",map);

    init_builtin_modules(root);

    process_alist(context, c);

    return root;
}

/***** Externally accessible functions */

atom_t intern(string_t s)
{
    struct atomlist *i;

    for (i=atoms; i; i=i->next) {
	if (strcmp(i->a, s)==0) break;
    }

    if (!i) {
	/* Did't find it; create a new one */
	i=safe_malloc(sizeof(*i),"intern: alloc list entry");
	i->a=safe_strdup(s,"intern: alloc string");
	i->next=atoms;
	atoms=i;
    }
    return i->a;
}

list_t *dict_lookup(dict_t *dict, string_t key)
{
    return dict_ilookup(dict, intern(key));
}

list_t *dict_lookup_primitive(dict_t *dict, string_t key)
{
    return dict_ilookup_primitive(dict, intern(key));
}

void dict_add(dict_t *dict, string_t key, list_t *val)
{
    dict_iadd(dict,intern(key),val);
}

string_t *dict_keys(dict_t *dict)
{
    atom_t *r, *j;
    struct entry *i;
    r=safe_malloc(sizeof(*r)*(dict->size+1),"dict_keys");
    for (i=dict->entries, j=r; i; i=i->next, j++) {
	*j=i->key;
    }
    *j=NULL;
    return r;
}


/* List-related functions */

list_t *list_new(void)
{
    return NULL;
}

uint32_t list_length(list_t *a)
{
    uint32_t l=0;
    list_t *i;
    for (i=a; i; i=i->next) l++;
    return l;
}

list_t *list_copy(list_t *a)
{
    list_t *r, *i, *b, *l;

    if (!a) return NULL;
    l=NULL;
    r=NULL;
    for (i=a; i; i=i->next) {
	b=safe_malloc(sizeof(*b),"list_copy");
	if (l) l->next=b; else r=b;
	l=b;
	b->item=i->item;
	b->next=NULL;
    }
    return r;
}

list_t *list_append_list(list_t *a, list_t *b)
{
    list_t *i;

    b=list_copy(b);
    if (!a) return b;
    for (i=a; i->next; i=i->next);
    i->next=b;
    return a;
}

list_t *list_append(list_t *list, item_t *item)
{
    list_t *l;

    l=safe_malloc(sizeof(*l),"list_append");
    l->item=item;
    l->next=NULL;

    return list_append_list(list,l);
}

item_t *list_elem(list_t *l, uint32_t index)
{
    if (!l) return NULL;
    if (index==0) return l->item;
    return list_elem(l->next, index-1);
}

list_t *new_closure(closure_t *cl)
{
    item_t *i;

    i=new_item(t_closure,no_loc);
    i->data.closure=cl;
    return list_append(NULL,i);
}

void add_closure(dict_t *dict, string_t name, apply_fn apply)
{
    closure_t *c;
    c=safe_malloc(sizeof(*c),"add_closure");
    c->description=name;
    c->apply=apply;
    c->interface=NULL;

    dict_add(dict,name,new_closure(c));
}

void *find_cl_if(dict_t *dict, string_t name, uint32_t type,
		 bool_t fail_if_invalid, string_t desc, struct cloc loc)
{
    list_t *l;
    item_t *i;
    closure_t *cl;

    l=dict_lookup(dict,name);
    if (!l) {
	if (!fail_if_invalid) return NULL;
	cfgfatal(loc,desc,"closure \"%s\" not found\n",name);
    }
    i=list_elem(l,0);
    if (i->type!=t_closure) {
	if (!fail_if_invalid) return NULL;
	cfgfatal(loc,desc,"\"%s\" must be a closure\n",name);
    }
    cl=i->data.closure;
    if (cl->type!=type) {
	if (!fail_if_invalid) return NULL;
	cfgfatal(loc,desc,"\"%s\" is the wrong type of closure\n",name);
    }
    return cl->interface;
}

/* Convenience functions for modules reading configuration dictionaries */
item_t *dict_find_item(dict_t *dict, string_t key, bool_t required,
		       string_t desc, struct cloc loc)
{
    list_t *l;
    item_t *i;

    l=dict_lookup(dict,key);
    if (!l) {
	if (!required) return NULL;
	cfgfatal(loc,desc,"required parameter \"%s\" not found\n",key);
    }
    i=list_elem(l,0);
    return i;
}

string_t dict_read_string(dict_t *dict, string_t key, bool_t required,
			  string_t desc, struct cloc loc)
{
    item_t *i;
    string_t r;

    i=dict_find_item(dict,key,required,desc,loc);
    if (!i) return NULL;
    if (i->type!=t_string) {
	cfgfatal(loc,desc,"\"%s\" must be a string\n",key);
    }
    r=i->data.string;
    return r;
}

uint32_t dict_read_number(dict_t *dict, string_t key, bool_t required,
			  string_t desc, struct cloc loc, uint32_t def)
{
    item_t *i;
    uint32_t r;

    i=dict_find_item(dict,key,required,desc,loc);
    if (!i) return def;
    if (i->type!=t_number) {
	cfgfatal(loc,desc,"\"%s\" must be a number\n",key);
    }
    r=i->data.number;
    return r;
}

bool_t dict_read_bool(dict_t *dict, string_t key, bool_t required,
		      string_t desc, struct cloc loc, bool_t def)
{
    item_t *i;
    bool_t r;

    i=dict_find_item(dict,key,required,desc,loc);
    if (!i) return def;
    if (i->type!=t_bool) {
	cfgfatal(loc,desc,"\"%s\" must be a boolean\n",key);
    }
    r=i->data.bool;
    return r;
}

static struct subnet string_to_subnet(item_t *i, string_t desc)
{
    struct subnet s;
    uint32_t a, b, c, d, n;
    uint32_t match;

    /* i is not guaranteed to be a string */
    if (i->type!=t_string) {
	cfgfatal(i->loc,desc,"expecting a string (subnet specification)\n");
    }

    /* We expect strings of the form "a.b.c.d[/n]", i.e. the dots are
       NOT optional. The subnet mask is optional; if missing it is assumed
       to be /32. */
    match=sscanf(i->data.string,"%u.%u.%u.%u/%u", &a, &b, &c, &d, &n);
    if (match<4) {
	cfgfatal(i->loc,desc,"\"%s\" is not a valid "
		 "subnet specification\n",i->data.string);
    }
    if (match<5) {
	n=32;
    }
    if (a>255 || b>255 || c>255 || d>255 || n>32) {
	cfgfatal(i->loc,desc,"\"%s\": range error\n",i->data.string);
    }
    s.prefix=(a<<24)|(b<<16)|(c<<8)|(d);
    s.mask=(~0UL << (32-n));
    s.len=n;
    if (s.prefix & ~s.mask) {
	cfgfatal(i->loc,desc,"\"%s\": prefix not fully contained "
		 "in mask\n",i->data.string);
    }
    return s;
}

uint32_t string_to_ipaddr(item_t *i, string_t desc)
{
    uint32_t a, b, c, d;
    uint32_t match;

    /* i is not guaranteed to be a string */
    if (i->type!=t_string) {
	cfgfatal(i->loc,desc,"expecting a string (IP address)\n");
    }

    match=sscanf(i->data.string,"%u.%u.%u.%u", &a, &b, &c, &d);
    if (match<4) {
	cfgfatal(i->loc,desc,"\"%s\" is not a valid "
		 "IP address\n",i->data.string);
    }
    if (a>255 || b>255 || c>255 || d>255) {
	cfgfatal(i->loc,desc,"\"%s\": range error\n",i->data.string);
    }
    return (a<<24)|(b<<16)|(c<<8)|(d);
}

void dict_read_subnet_list(dict_t *dict, string_t key, bool_t required,
			   string_t desc, struct cloc loc,
			   struct subnet_list *sl)
{
    list_t *l, *li;
    item_t *i;
    uint32_t e=0;

    sl->entries=0;
    sl->list=NULL;
    l=dict_lookup(dict, key);
    if (!l) {
	if (!required) return;
	cfgfatal(loc,desc,"required parameter \"%s\" not found\n",key);
    }
    /* Count the items in the list */
    for (li=l; li; li=li->next) e++;
    if (e==0) return;
    sl->entries=e;
    sl->list=safe_malloc(sizeof(struct subnet)*e, "dict_read_subnet_list");
    e=0;
    /* Fill in the list */
    for (li=l; li; li=li->next) {
	i=li->item;
	if (i->type!=t_string) {
	    cfgfatal(loc,desc,"parameter \"%s\": all elements must "
		     "be strings\n",key);
	}
	sl->list[e++]=string_to_subnet(i,desc);
    }
}

uint32_t string_to_word(string_t s, struct cloc loc,
			struct flagstr *f, string_t desc)
{
    struct flagstr *j;
    for (j=f; j->name; j++)
	if (strcmp(s,j->name)==0)
	    return j->value;
    cfgfatal(loc,desc,"option \"%s\" not known\n",s);
    return 0;
}

uint32_t string_list_to_word(list_t *l, struct flagstr *f, string_t desc)
{
    list_t *i;
    uint32_t r=0;
    struct flagstr *j;

    for (i=l; i; i=i->next) {
	if (i->item->type!=t_string) {
	    cfgfatal(i->item->loc,desc,"all elements of list must be "
		     "strings\n");
	}
	for (j=f; j->name; j++)
	    r|=string_to_word(i->item->data.string,i->item->loc,f,desc);
    }
    return r;
}

dict_t *read_conffile(char *name)
{
    FILE *conffile;
    struct p_node *config;

    if (strcmp(name,"-")==0) {
	conffile=stdin;
    } else {
	conffile=fopen(name,"r");
	if (!conffile)
	    fatal_perror("Cannot open configuration file \"%s\"",name);
    }
    config_lineno=1;
    config_file=name;
    config=parse_conffile(conffile);
    fclose(conffile);

#ifdef DUMP_PARSE_TREE
    printf("*** config file parse tree BEFORE MANGLE\n");
    ptree_dump(config,0);
#endif /* DUMP_PARSE_TREE */
    /* The root of the configuration is a T_ALIST, which needs reversing
       before we mangle because it isn't the child of a T_DICT. */
    config=list_reverse(config);
    ptree_mangle(config);
#ifdef DUMP_PARSE_TREE
    printf("\n\n*** config file parse tree AFTER MANGLE\n");
    ptree_dump(config,0);
#endif /* DUMP_PARSE_TREE */
    return process_config(config);
}
