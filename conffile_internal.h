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

#ifndef conffile_internal_h
#define conffile_internal_h

#include <stdio.h>
#include "secnet.h"

typedef cstring_t atom_t;

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
	string_t string;
	uint32_t number;
    } data;
    struct p_node *l;
    struct p_node *r;
};

extern cstring_t config_file;
extern int config_lineno;
extern int yynerrs;

/* Keys in dictionaries are 'atoms', which are constructed from strings
   using this call. Atoms may be compared using '=='. */
extern atom_t intern(cstring_t string);

extern struct p_node *parse_conffile(FILE *conffile);

#endif /* conffile_internal_h */
