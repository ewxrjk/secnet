#!/usr/bin/perl -w
# -*- C -*-
#
# secnet - pubkeys.fl.pl
#
# This file is part of secnet.
# See README for full list of copyright holders.
#
# secnet is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# secnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# version 3 along with secnet; if not, see
# https://www.gnu.org/licenses/gpl.html.

# We process __DATA__ of this file first through the perl code,
# and then through flex.  We do it like this because directives
# with positional arguments are otherwise rather tedious to specify
# in flex.  Of course we could have used bison too but this seems
# better overall.

use strict;

our $do = '';
our $co = '';
our $kw;
our $kwid;
our @next_kw;
our $in_s;
our $data_off;

our %subst = (GRPIDSZ => 4, SERIALSZ => 4);

our $last_lno = -1;
sub lineno (;$$) {
    my ($always, $delta) = @_;
    my $o = '';
    $delta //= 0;
    if ($always || $. != $last_lno+1) {
	$o .= sprintf "#line %d \"%s\"\n", $delta+$data_off+$., $0;
    }
    $last_lno = $.;
    $o;
}

while (<DATA>) {
	last if m/^\%\%\s*$/;
	if (m/^!SUBSTCHECKS\s*$/) {
		foreach (keys %subst) {
			$do .= <<END
#if $_ != $subst{$_}
# error $_ value disagrees between pubkeys.fl.pl and C headers
#endif
END
		}
		next;
	}
	$do .= lineno();
	$do .= $_;
}

sub inst ($) {
	$do .= "%x $_[0]\n";
	"<$_[0]>";
}

while (<DATA>) {
    s#\{!2(\w+)\}# '{'.(2 * ($subst{$1}//die "$1 ?")).'}' #ge;
    if (m/^!(KEYWORD|KWALIAS) ([-0-9a-z]+)(\s*\{.*\})?$/) {
	my $kwt=$2;
	if ($1 eq 'KEYWORD') {
	    die if $kw;
	    $kw = $kwt;
	} else {
	    die if @next_kw;
	    die unless $kw;
	}
	my $xact = $3 // '';
	$kwid = $kw; $kwid =~ y/-/_/;
	$in_s = "HK_${kwid}";
	$co .= "{L}$kwt { BEGIN($in_s); $xact }\n";
	next;
    }
    if (m/^!ARG (\w+) (\S.*\S) \{\s*$/) {
	die unless $kw;
	die if @next_kw;
	$co .= inst("$in_s")."{S} { BEGIN(D_${kwid}_$1); }\n";
	$co .= inst("D_${kwid}_$1")."$2 {\n";
	$in_s = "HA_${kwid}_$1";
	$co .= "\tBEGIN($in_s);\n";
	@next_kw = ($kw);
	$co .= lineno(1,1);
	next;
    }
    if (m/^!\}\s*$/) {
	die unless @next_kw;
	$co .= lineno(1,0);
	$co .= "}\n";
	$kw = shift @next_kw;
	next;
    }
    if (m/^!FINAL \{\s*$/) {
	die unless $kw;
	die if @next_kw;
	$co .= inst("FIN_$kwid")."\\n { BEGIN(0); c->loc.line++; }\n";
	$co .= inst("$in_s")."{L}/\\n {\n";
	$co .= "\tBEGIN(FIN_$kwid);\n";
	$co .= lineno(1,1);
	@next_kw = (undef);
	next;
    }
    if (m/^!/) {
	die;
    }
    $co .= $_;
    if (m/^\%\%\s*$/) {
	$co .= lineno(1,1);
    }
}

print $do, "%%\n", $co or die $!;

BEGIN { $data_off = __LINE__ + 1; }
__DATA__

L	[ \t]*
S	[ \t]+
BASE91S	[]-~!#-&(-[]+
%x SKIPNL

%option yylineno
%option noyywrap
%option batch
%option 8bit
%option nodefault
%option never-interactive

%option prefix="pkyy"

%option warn

%{

#include "secnet.h"
#include "pubkeys.h"
#include "util.h"
#include "unaligned.h"
#include "base91s/base91.h"

!SUBSTCHECKS

struct pubkeyset_context {
    /* filled in during setup: */
    struct cloc loc; /* line is runtime */
    struct log_if *log;
    struct buffer_if *data_buf;
    struct peer_keyset *building;
    /* runtime: */
    bool_t had_serial;
    bool_t fallback_skip;
    const struct sigscheme_info *scheme;
    uint8_t grpid[GRPIDSZ];
    serialt serial;
};

static struct pubkeyset_context c[1];

#define LI (c->log)
#define HEX2BIN(v,l) ({							\
	int32_t outlen;							\
	bool_t ok=hex_decode((v), ((l)), &outlen, yytext, False);	\
	assert(ok);							\
	assert(outlen==((l)));						\
    })
#define HEX2BIN_ARRAY(v) HEX2BIN((v),sizeof((v)))
#define DOSKIPQ ({					\
        BEGIN(SKIPNL);					\
        break;						\
    })
#define DOSKIP(m) ({					\
        slilog(LI,M_INFO,"%s:%d: " m, c->loc.file, c->loc.line);	\
        DOSKIPQ;					\
    })
#define FAIL(m) do{					\
	slilog(LI,M_ERR,"%s:%d: " m, c->loc.file, c->loc.line);	\
	return -1;					\
    }while(0)

%}

%%

!KEYWORD pkg  { c->fallback_skip=0; }
!KWALIAS pkgf { c->fallback_skip=!!c->building->nkeys; }
!ARG id [0-9a-f]{!2GRPIDSZ} {
    HEX2BIN_ARRAY(c->grpid);
!}
!FINAL {
!}
!KEYWORD pub
!ARG algo [-0-9a-z]+ {
    if (c->fallback_skip) DOSKIP("fallback not needed");
    c->scheme = sigscheme_lookup(yytext);
    if (!c->scheme) DOSKIP("unknown pk algorithm");
!}
!ARG data {BASE91S} {
    /* baseE91 and thus base91s can sometimes store 14 bits per
     * character pair, so the max decode ratio is 14/16. */
    size_t maxl = base91s_decode_maxlen(yyleng);
    buffer_init(c->data_buf,0);
    if (buf_remaining_space(c->data_buf) < maxl) DOSKIP("pk data too long");
    struct base91s b91;
    base91s_init(&b91);
    size_t l = base91s_decode(&b91, yytext, yyleng, c->data_buf->start);
    l += base91s_decode_end(&b91, c->data_buf->start + l);
    assert(l <= maxl);
    buf_append(c->data_buf,l);
!}
!FINAL {
    if (c->building->nkeys >= MAX_SIG_KEYS) DOSKIP("too many public keys");
    struct sigpubkey_if *pubkey;
    bool_t ok=c->scheme->loadpub(c->scheme,c->data_buf,
				 &pubkey,c->log);
    if (!ok) break;
    memcpy(c->building->keys[c->building->nkeys].id.b,
	   c->grpid,
           GRPIDSZ);
    assert(ALGIDSZ==1); /* otherwise need htons or htonl or something */
    c->building->keys[c->building->nkeys].id.b[GRPIDSZ]=
      c->scheme->algid;
    c->building->keys[c->building->nkeys++].pubkey=pubkey;
!}

!KEYWORD serial
!ARG id [0-9a-f]{!2SERIALSZ} {
    if (c->had_serial) FAIL("`serial' repeated");
    c->had_serial = 1;
    uint8_t sb[SERIALSZ];
    HEX2BIN_ARRAY(sb);
    c->serial=get_uint32(sb);
!}
!FINAL {
!}

{L}[-0-9a-z]+ {
    DOSKIP("unknown directive");
}

{L}\# {
    BEGIN(SKIPNL);
}
{L}\n {
    c->loc.line++;
}

<SKIPNL>.*\n {
    c->loc.line++;
    BEGIN(0);
}

<INITIAL><<EOF>>	{ return 0; }

<*>. { FAIL("syntax error"); }
<*>\n { FAIL("syntax error - unexpected newline"); }
<<EOF>> { FAIL("syntax error - unexpected eof"); }

%%

extern struct peer_keyset *
keyset_load(const char *path, struct buffer_if *data_buf,
	    struct log_if *log, int logcl_enoent) {
    assert(!c->building);
    c->log=log;
    c->loc.file=path;
    pkyyin = fopen(path, "r");
    if (!pkyyin) {
	slilog(LI,
	       errno==ENOENT ? logcl_enoent : M_ERR,
	       "could not open keyset file %s: %s",
	       path,strerror(errno));
	goto err;
    }

    pkyyrestart(pkyyin);
    BEGIN(0);
    c->data_buf=data_buf;
    NEW(c->building);
    c->building->nkeys=0;
    c->building->refcount=1;
    c->fallback_skip=0;
    c->had_serial=0;
    c->loc.line=1;
    FILLZERO(c->grpid);
    FILLZERO(c->serial);
    int r=pkyylex();
    if (r) goto err_bad;

    if (!c->had_serial) {
	slilog(LI,M_ERR,"missing serial number in %s",path);
	goto err_bad;
    }
    if (!c->building->nkeys) {
	slilog(LI,M_ERR,"no useable keys in %s",path);
	goto err_bad;
    }
    fclose(pkyyin);
    struct peer_keyset *built=c->building;
    c->building=0;
    return built;

 err_bad:
    errno=EBADMSG;
 err:
    if (c->building) { free(c->building); c->building=0; }
    if (pkyyin) { fclose(pkyyin); pkyyin=0; }
    return 0;
}

