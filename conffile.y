%token TOK_STRING
%token TOK_NUMBER
%token TOK_KEY

%start input

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "secnet.h"
#include "conffile_internal.h"
#include "conffile.yy.h"
#include "util.h"
#define YYERROR_VERBOSE

static struct p_node *node(uint32_t type, struct p_node *l, struct p_node *r);

static struct p_node *result;

static void yyerror(const char *s);

%}

%%

input:		  assignments { result = $1; $$=result; }
		;

assignments:	  assignments assignment { $$=node(T_ALIST, $2, $1); }
		| assignment { $$=node(T_ALIST, $1, NULL); }
		;

searchpath:	  /* empty */ { $$ = NULL; }
		| '<' list '>' { $$ = $2; }
		;

dict:		  searchpath '{' assignments '}'
	{ $$ = node(T_DICT, $3, $1); }
		| searchpath '{' '}' { $$ = node(T_DICT, NULL, $1); }
		;

path:		  '/' pathelements { $$ = node(T_ABSPATH, NULL, $2); }
		| pathelements { $$ = node(T_RELPATH, NULL, $1); }
		;

pathelements:	  pathelements '/' TOK_KEY { $$ = node(T_PATHELEM, $3, $1); }
		| TOK_KEY { $$ = node(T_PATHELEM, $1, NULL); }
		;

exec:		  item '(' list ')' { $$ = node(T_EXEC, $1, $3); }
		| item '(' ')' { $$ = node(T_EXEC, $1, NULL); }
		| item dict
	{ $$ = node(T_EXEC, $1, node(T_LISTITEM, $2, NULL)); }
		;

list:		  list ',' item { $$ = node(T_LISTITEM, $3, $1); }
		| item { $$ = node(T_LISTITEM, $1, NULL); }
		;

assignment:	  TOK_KEY '=' list ';' { $$ = node(T_ASSIGNMENT, $1, $3); }
		| TOK_KEY list ';' { $$ = node(T_ASSIGNMENT, $1, $2); }
		| error ';' { $$ = node(T_ERROR, NULL, NULL); }
		| error '}' { $$ = node(T_ERROR, NULL, NULL); }
		| error ')' { $$ = node(T_ERROR, NULL, NULL); }
		;

item:		  TOK_STRING
		| TOK_NUMBER
		| path
		| dict
		| exec
		;

%%

static void yyerror(const char *s)
{
	Message(M_FATAL,"config file %s line %d: %s\n",config_file,
		config_lineno,s);
}

struct p_node *parse_conffile(FILE *conffile)
{
	yyin=conffile;
	if (yyparse()!=0) {
		fatal("Configuration file parsing failed\n");
	}
	if (yynerrs>0) {
		fatal("%d error%s encountered in configuration file\n",
		yynerrs,yynerrs==1?"":"s");
	}
	return result;
}

static struct p_node *node(uint32_t type, struct p_node *l, struct p_node *r)
{
	struct p_node *rv;

	rv=safe_malloc(sizeof(*rv),"p_node");
	rv->type=type;
	rv->loc.file=config_file;
	rv->loc.line=config_lineno;
	rv->l=l;
	rv->r=r;
	return rv;
}
