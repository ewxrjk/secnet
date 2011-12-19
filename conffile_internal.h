#ifndef conffile_internal_h
#define conffile_internal_h

#include <stdio.h>
#include "secnet.h"

typedef const char *atom_t;

/* Parse tree for configuration file */

#define YYSTYPE struct p_node *

#define T_STRING 1
#define T_NUMBER 2
#define T_KEY    3
#define T_ASSIGNMENT 10
#define T_LISTITEM   11
#define T_EXEC       12
#define T_PATHELEM   13
#define T_ABSPATH    14
#define T_RELPATH    15
#define T_DICT       16
#define T_ALIST      17
#define T_ERROR      20

#define T_IS_PRIMITIVE(NTYPE) ((NTYPE) < T_ASSIGNMENT)

struct p_node {
    uint32_t type;
    struct cloc loc;
    union {
	atom_t key;
	char *string;
	uint32_t number;
    } data;
    struct p_node *l;
    struct p_node *r;
};

extern const char *config_file;
extern int config_lineno;
extern int yynerrs;

/* Keys in dictionaries are 'atoms', which are constructed from strings
   using this call. Atoms may be compared using '=='. */
extern atom_t intern(const char *string);

extern struct p_node *parse_conffile(FILE *conffile);

#endif /* conffile_internal_h */
