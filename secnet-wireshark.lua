--- -*-lua-*-
---
--- This file is part of secnet.
--- See README for full list of copyright holders.
---
--- secnet is free software; you can redistribute it and/or modify it
--- under the terms of the GNU General Public License as published by
--- the Free Software Foundation; either version d of the License, or
--- (at your option) any later version.
---
--- secnet is distributed in the hope that it will be useful, but
--- WITHOUT ANY WARRANTY; without even the implied warranty of
--- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
--- General Public License for more details.
---
--- You should have received a copy of the GNU General Public License
--- version 3 along with secnet; if not, see
--- https://www.gnu.org/licenses/gpl.html.

local secnet = Proto("secnet", "Secnet VPN")

-----------------------------------------------------------------------------
--- Session tracking.
---
--- This is the hardest part of the dissector.

-- Timelines.  A timeline associates pieces of information with times T.

local function tl_new()
  -- Return a fresh shiny timeline.

  return { }
end

local function tl__find(tl, t)
  -- Find and return the earliest association in TL not earlier than T.  If
  -- there is no such entry, return nil.

  local lo = 1
  local hi = #tl + 1

  -- Plain old binary search.  The active interval is half-open, [lo, hi).
  while true do
    local w = hi - lo
    if w == 0 then return nil end
    local mid = lo + math.floor(w/2)
    local tv = tl[mid]
    if tv.t > t then hi = mid
    elseif tv.t == t or w == 1 then return tv
    else lo = mid
    end
  end
end

local function tl_find(tl, t)
  -- Find and return the state of the timeline at time T, i.e., the earliest
  -- value in TL not earlier than T.  If there is no such entry, return nil.

  local tv = tl__find(tl, t)
  if tv == nil then return nil else return tv.v end
end

local function tl_add(tl, t, v)
  -- Associate the value V with time T in TL.

  local tv = tl__find(tl, t)
  if tv ~= nil and tv.t == t then
    tv.v = v
  else
    -- Append the new item.  If necessary, sort the vector; we expect that
    -- we'll see everything in the right order, so this won't be a problem.
    local n = #tl
    tl[n + 1] = { t = t, v = v }
    if n > 0 and tl[n].t > t then
      table.sort(tl, function (tv0, tv1) return tv0.t < tv1.t end)
    end
  end
end

local function dump_timeline(tl, cvt)
  -- Dump a timeline TL, using the function CVT to convert each value to a
  -- string.

  for _, tv in ipairs(tl) do print("\t" .. tv.t .. ": " .. cvt(tv.v)) end
end

local function get_timeline_create(map, index)
  -- If MAP[INDEX] exists, return it; otherwise set MAP[INDEX] to a fresh
  -- timeline and return that.

  local tl = map[index]
  if tl == nil then tl = tl_new(); map[index] = tl end
  return tl
end

local function lookup_timeline(map, index, t)
  -- If it exists, MAP[INDEX] should be a timeline; find its state at time T.
  -- Return nil if there's nothing there, or T is too early.

  local tl = map[index]
  if tl == nil then return nil
  else return tl_find(tl, t)
  end
end

-- The `SITEMAP' maps site names to little structures.
--
--   * `algs' is a map from peer site names to a timeline of structures
--     described below.
--
--   * `index' is a map from site indices to a timeline of names, reflecting
--     that, at some time T, this site thought that some index I referred to
--     a peer site P.
--
-- The `algs' map contains the following slots, populated during .
--
--   * `xform' is a timeline of transform names.
local SITEMAP = { }

-- The `ADDRMAP' maps (IPv4 or IPv6) socket addresses in the form
-- `[ADDR]:PORT' to a timeline of site names, populated based on claims made
-- by senders about themselves.  The `GUESSMAP' is similar, but populated
-- based on assertions about recipients.
local ADDRMAP = { }
local GUESSMAP = { }

local function snd_sockname(st)
  -- Return the sender's socket name as a thing which can be used as a table
  -- index.

  local pinfo = st.pinfo
  return string.format("[%s]:%d", pinfo.net_src, pinfo.src_port)
end

local function rcv_sockname(st)
  -- Return the recipient's socket name as a thing which can be used as a
  -- table index.

  local pinfo = st.pinfo
  return string.format("[%s]:%d", pinfo.net_dst, pinfo.dst_port)
end

local function get_site_create(name)
  -- If NAME refers to a known site, then return its information structure;
  -- otherwise create a new one and return that.

  local site = SITEMAP[name]
  if site == nil then
    site = { algs = { }, index = { } }
    SITEMAP[name] = site
  end
  return site
end

local function notice_site_name(map, st, sock, name)
  -- Record in MAP that the packet described in the state ST tells us that,
  -- at that time, the site NAME appeared to be at address SOCK.

  tl_add(get_timeline_create(map, sock), st.pinfo.rel_ts, name)
end

local function dump_algs(algs)
  -- Dump the algorithms selection ALGS from a site structure.

  return "xform=" .. algs.transform
end

local function dump_str(str) return str end

local function dump_addrmap(what, map)
  -- Dump MAP, which is an address map like `ADDRMAP' or `GUESSMAP'; WHAT is
  -- a string describing which map it is.

  print(what .. "...")
  for addr, tl in pairs(map) do
    print("  " .. addr)
    dump_timeline(tl, dump_str)
  end
end

local function dump_tracking_state()
  -- Dump the entire tracking state to standard output.

  dump_addrmap("Address map", ADDRMAP)
  dump_addrmap("Guess map", GUESSMAP)
  print("Site map...")
  for name, site in pairs(SITEMAP) do
    print("  " .. name)
    print("    algs...")
    for peer, tl in pairs(site.algs) do
      print("      " .. peer)
      dump_timeline(tl, dump_algs)
    end
    print("    index...")
    for ix, tl in pairs(site.index) do
      print("      " .. ix)
      dump_timeline(tl, dump_str)
    end
  end
end

local function notice_sndname(st, name)
  -- Record that sender of the packet described by state ST is called NAME.

  st.sndname = name
  notice_site_name(ADDRMAP, st, snd_sockname(st), name)
end

local function notice_rcvname(st, name)
  -- Record that the sender of the packet described by ST thought that its
  -- recipient was called NAME.

  st.rcvname = name
  notice_site_name(GUESSMAP, st, rcv_sockname(st), name)
  if st.sndname ~= nil then
    local site = get_site_create(st.sndname)
    tl_add(get_timeline_create(site.index, st.sndix), st.pinfo.rel_ts, name)
  end
end

-- Tables describing the kinds of algorithms which can be selected.
local CAPTAB = {
  [8] = { name = "serpent256cbc", kind = "transform",
	  desc = "Deprecated Serpent256-CBC transform" },
  [9] = { name = "eaxserpent", kind = "transform",
	  desc = "Serpent256-EAX transform" },
  [31] = { name = "mobile-priority", kind = "early",
	   desc = "Mobile site takes priority in case of MSG1 crossing" }
}

local function get_algname(kind, cap, dflt)
  -- Fetch an algorithm of the given KIND, given its capability number CAP;
  -- if CAP is nil, then return DFLT instead.

  local name
  if cap == nil then
    name = dflt
  else
    local info = CAPTAB[cap]
    if info ~= nil and info.kind == kind then name = info.name
    else name = string.format("Unknown %s #%d", kind, cap)
    end
  end
  return name
end

local function notice_alg_selection(st)
  -- Record the algorithm selections declared in the packet described by ST.

  local transform = get_algname("transform", st.transform, "serpent256cbc")
  local site = get_site_create(st.sndname)
  local peer = get_site_create(st.rcvname)
  local now = st.pinfo.rel_ts
  local algs = { transform = transform }
  tl_add(get_timeline_create(site.algs, st.rcvname), now, algs)
  tl_add(get_timeline_create(peer.algs, st.sndname), now, algs)
end

-----------------------------------------------------------------------------
--- Protocol dissection primitives.

local PF = { } -- The table of protocol fields, filled in later.
local F = { } -- A table of field values, also filled in later.

-- Main message-number table.
local M = { NAK		= 0x00000000
	    MSG0	= 0x00020200
	    MSG1	= 0x01010101
	    MSG2	= 0x02020202
	    MSG3	= 0x03030303
	    MSG3BIS	= 0x13030313
	    MSG4	= 0x04040404
	    MSG5	= 0x05050505
	    MSG6	= 0x06060606
	    MSG7	= 0x07070707
	    MSG8	= 0x08080808
	    MSG9	= 0x09090909
	    PROD	= 0x0a0a0a0a }

-- The `dissect_*' functions follow a common protocol.  They parse a thing
-- from a packet buffer BUF, of size SZ, starting from POS, and store
-- interesting things in a given TREE; when they're done, they return the
-- updated index where the next interesting thing might be, and maybe store
-- interesting things in the state ST.  As a result, it's usually a simple
-- matter to parse a packet by invoking the appropriate primitive dissectors
-- in the right order.

local function dissect_sequence(dissect, st, buf, tree, pos, sz)
  -- Dissect pieces of the packed in BUF with each of the dissectors in the
  -- list DISSECT in turn.

  for _, d in ipairs(dissect) do pos = d(st, buf, tree, pos, sz) end
  return pos
end

local function dissect_wtf(st, buf, tree, pos, sz)
  -- If POS is not at the end of the buffer, note that there's unexpected
  -- stuff in the packet.

  if pos < sz then tree:add(PF["secnet.wtf"], buf(pos, sz - pos)) end
  return sz
end

local dissect_caps
do
  -- This will be a list of the capability protocol field names, in the right
  -- order.  We just have to figure out what that will be.
  local caplist = { }

  do
    local caps = { }

    -- Firstly, build, in `caps', a list of the capability names and their
    -- numbers.
    local i = 1
    for j, cap in pairs(CAPTAB) do
      caps[i] = { i = j, cap = cap.name }
      i = i + 1
    end

    -- Sort the list.  Now they're in the right order.
    table.sort(caps, function (v0, v1) return v0.i < v1.i end)

    -- Finally, write the entries to `caplist', with the `user' entry at the
    -- start and the `unassigned' entry at the end.
    i = 1
    caplist[i] = "secnet.cap.user"; i = i + 1
    for _, v in ipairs(caps) do
      caplist[i] = "secnet.cap." .. v.cap
      i = i + 1
    end
    caplist[i] = "secnet.cap.unassigned"; i = i + 1
  end

  function dissect_caps(st, buf, tree, pos, sz)
    -- Dissect a capabilities word.

    if pos < sz then
      local cap = tree:add(PF["secnet.cap"], buf(pos, 4))
      for _, pf in ipairs(caplist) do cap:add(PF[pf], buf(pos, 4)) end
      pos = pos + 4
    end
    return pos
  end
end

local function dissect_mtu(st, buf, tree, pos, sz)
  -- Dissect an MTU request.

  if pos < sz then tree:add(PF["secnet.mtu"], buf(pos, 2)); pos = pos + 2 end
  return pos
end

local function make_dissect_name_xinfo(label, dissect_xinfo, hook)
  -- Return a dissector function for reading a name and extra information.
  -- The function will dissect a subtree rooted at the protocol field LABEL;
  -- it will dissect the extra information using the list DISSECT_XINFO
  -- (processed using `dissect_sequence'); and finally, if the packet hasn't
  -- been visited yet, it will call HOOK(ST, NAME), where NAME is the name
  -- string extracted from the packet.

  return function (st, buf, tree, pos, sz)

    -- Find the length of the whole thing.
    local len = buf(pos, 2):uint()

    -- Make the subtree root.
    local sub = tree:add(PF[label], buf(pos, len + 2))

    -- Find the length of the name.  This is rather irritating: I'd like to
    -- get Wireshark to do this, but it seems that `stringz' doesn't pay
    -- attention to the buffer limits it's given.  So read the whole lot and
    -- find the null by hand.
    local name = buf(pos + 2, len):string()
    local z, _ = string.find(name, "\0", 1, true)
    if z == nil then
      z = len
    else
      z = z - 1
      name = string.sub(name, 1, z)
    end

    -- Fill in the subtree.
    sub:add(PF["secnet.namex.len"], buf(pos, 2)); pos = pos + 2
    sub:add(PF["secnet.namex.name"], buf(pos, z))
    if z < len then
      dissect_sequence(dissect_xinfo, st, buf, sub, pos + z + 1, pos + len)
    end

    -- Maybe call the hook.
    if hook ~= nil and not st.pinfo.visited then hook(st, name) end

    -- We're done.
    return pos + len
  end
end

local function dissect_sndnonce(st, buf, tree, pos, sz)
  -- Dissect the sender's nonce.

  tree:add(PF["secnet.kx.sndnonce"], buf(pos, 8)); pos = pos + 8
  return pos
end

local function dissect_rcvnonce(st, buf, tree, pos, sz)
  -- Dissect the recipient's nonce.

  tree:add(PF["secnet.kx.rcvnonce"], buf(pos, 8)); pos = pos + 8
  return pos
end

local function dissect_transform(st, buf, tree, pos, sz)
  -- Dissect the selected transform.  Note this in the packet state for
  -- later.

  st.transform = buf(pos, 1):uint()
  tree:add(PF["secnet.kx.transform"], buf(pos, 1)); pos = pos + 1
  return pos
end

local function dissect_lenstr(st, buf, tree, label, pos, sz)
  -- Dissect a simple string given its length.
  local len = buf(pos, 2):uint()
  local sub = tree:add(PF[label], buf(pos, len + 2))
  sub:add(PF[label .. ".len"], buf(pos, 2)); pos = pos + 2
  sub:add(PF[label .. ".text"], buf(pos, len)); pos = pos + len
  return pos
end

local function dissect_dhval(st, buf, tree, pos, sz)
  -- Dissect a Diffie--Hellman public value.

  return dissect_lenstr(st, buf, tree, "secnet.kx.dhval", pos, sz)
end

local function dissect_sig(st, buf, tree, pos, sz)
  -- Dissect a signature.

  return dissect_lenstr(st, buf, tree, "secnet.kx.sig", pos, sz)
end

local function find_algs_lookup(map, sock, now, ix)
  -- Utility for `find_algs': look SOCK up in the address map ADDR, to find a
  -- site; find its peer with index IX; and return the algorithm selection
  -- current between the pair at time NOW.  If the lookup fails, return nil.

  local name = lookup_timeline(map, sock, now)
  if name == nil then return nil end
  local site = SITEMAP[name]
  if site == nil then return nil end
  local peername = lookup_timeline(site.index, ix, now)
  if peername == nil then return nil end
  return lookup_timeline(site.algs, peername, now)
end

local function find_algs(st)
  -- Return the algorithm selection which applies to the packet described in
  -- ST.

  local now = st.pinfo.rel_ts
  local sock = snd_sockname(st)
  local algs = find_algs_lookup(ADDRMAP, sock, now, st.sndix)
  if algs ~= nil then return algs
  else return  find_algs_lookup(GUESSMAP, sock, now, st.rcvix)
  end
end

-- Transform-specific dissectors...
local dissect_ct = { }
function dissect_ct.unknown(st, why, buf, tree, pos, sz)
  tree:add(PF["secnet.ciphertext.unknown"], buf(pos, sz - pos),
	   "Ciphertext with unknown structure: " .. why)
  return sz
end
function dissect_ct.serpent256cbc(st, buf, tree, pos, sz)
  tree:add(PF["secnet.ciphertext.iv"], buf(pos, 4)); pos = pos + 4
  tree:add(PF["secnet.ciphertext.payload"], buf(pos, sz - pos))
  return sz
end
function dissect_ct.eaxserpent(st, buf, tree, pos, sz)
  local len = sz - pos - 20
  tree:add(PF["secnet.ciphertext.payload"], buf(pos, len)); pos = pos + len
  tree:add(PF["secnet.ciphertext.tag"], buf(pos, 16)); pos = pos + 16
  tree:add(PF["secnet.ciphertext.sequence"], buf(pos, 4)); pos = pos + 4
  return pos
end

local function dissect_ciphertext(st, buf, tree, pos, sz)
  -- Dissect a ciphertext.

  local sub = tree:add(PF["secnet.ciphertext"], buf(pos, sz - pos))
  local algs = find_algs(st)
  local xform
  if algs == nil then xform = nil else xform = algs.transform end
  if xform == nil then
    pos = dissect_ct.unknown(st, "unable to find negotiated transform",
			     buf, sub, pos, sz)
  else
    local func = dissect_ct[xform]
    if func == nil then
      pos = dissect_ct.unknown(st, "unsupported transform " .. xform,
			       buf, sub, pos, sz)
    else
      pos = func(st, buf, sub, pos, sz)
    end
  end
  return pos
end

-----------------------------------------------------------------------------
--- The protocol information table.

local PKTINFO = {
  -- This is the main table which describes the protocol.  The top level maps
  -- message labels to structures:
  --
  --   * `label' is the category code's symbolic name;
  --
  --   * `info' is a prefix for the information column display; and
  --
  --   * `dissect' is a sequence of primitive dissectors to run in order to
  --     parse the rest of the packet.

  [M.NAK] = {
    label = "NAK",
    info = "Stimulate fresh key exchange",
    dissect = { dissect_wtf }
  },
  [M.MSG0] = {
    label = "MSG0",
    info = "MSG0",
    dissect = { dissect_ciphertext }
  },
  [M.MSG1] = {
    label = "MSG1",
    info = "MSG1",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps, dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_sndnonce,
		dissect_wtf }
  },
  [M.MSG2] = {
    label = "MSG2",
    info = "MSG2",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps, dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_sndnonce, dissect_rcvnonce,
		dissect_wtf }
  },
  [M.MSG3] = {
    label = "MSG3",
    info = "MSG3",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps,
					  dissect_mtu,
					  dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_sndnonce, dissect_rcvnonce,
		dissect_wtf },
    hook = notice_alg_selection
  },
  [M.MSG3BIS] = {
    label = "MSG3BIS",
    info = "MSG3BIS",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps,
					  dissect_mtu,
					  dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_sndnonce, dissect_rcvnonce,
		dissect_transform,
		dissect_dhval, dissect_sig,
		dissect_wtf },
    hook = notice_alg_selection
  },
  [M.MSG4] = {
    label = "MSG4",
    info = "MSG4",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps,
					  dissect_mtu,
					  dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_sndnonce, dissect_rcvnonce,
		dissect_dhval, dissect_sig,
		dissect_wtf }
  },
  [M.MSG5] = {
    label = "MSG5",
    info = "MSG5",
    dissect = { dissect_ciphertext }
  },
  [M.MSG6] = {
    label = "MSG6",
    info = "MSG6",
    dissect = { dissect_ciphertext }
  },
  [M.PROD] = {
    label = "PROD",
    info = "PROD",
    dissect = { make_dissect_name_xinfo("secnet.kx.sndname",
					{ dissect_caps,
					  dissect_wtf },
					notice_sndname),
		make_dissect_name_xinfo("secnet.kx.rcvname",
					{ dissect_wtf },
					notice_rcvname),
		dissect_wtf }
  },
}

do
  -- Work through the master table and build the `msgtab'' table, mapping
  -- message codes to their symbolic names for presentation.
  local msgtab = { }
  for i, v in pairs(PKTINFO) do msgtab[i] = v.label end

  local capmap = { transform = { }, early = { } }
  for i, v in pairs(CAPTAB) do capmap[v.kind][i] = v.desc end

  local ftab = {
    -- The protocol fields.  This table maps the field names to structures
    -- used to build the fields, which are then stored in `PF' (declared way
    -- above):
    --
    --   * `name' is the field name to show in the dissector tree view;
    --
    --   * `type' is the field type;
    --
    --   * `base' is a tweak describing how the field should be formatted;
    --
    --   * `mask' is used to single out a piece of a larger bitfield;
    --
    --   * `tab' names a mapping table used to convert numerical values to
    --     symbolic names; and
    --
    --   * `hook' is a hook function to run the first time we see a packet,
    --     to keep track of things.

    ["secnet.hdr"] = {
      name = "Common message header", type = ftypes.NONE
    },
    ["secnet.hdr.rcvix"] = {
      name = "Recipient's site index for sender",
      type = ftypes.UINT32, base = base.DEC
    },
    ["secnet.hdr.sndix"] = {
      name = "Sender's site index for recipient",
      type = ftypes.UINT32, base = base.DEC
    },
    ["secnet.hdr.label"] = {
      name = "Message label", type = ftypes.UINT32,
      base = base.HEX, tab = msgtab
    },
    ["secnet.kx.sndname"] = {
      name = "Sender's site name and extended information",
      type = ftypes.NONE
    },
    ["secnet.kx.rcvname"] = {
      name = "Recipient's site name and extended information",
      type = ftypes.NONE
    },
    ["secnet.namex.len"] = {
      name = "Name/extended info length",
      type = ftypes.UINT16, base = base.DEC
    },
    ["secnet.namex.name"] = {
      name = "Site name", type = ftypes.STRING,
      field = true, base = base.ASCII,
    },
    ["secnet.cap"] = {
      name = "Advertised capability bits",
      type = ftypes.UINT32, base = base.HEX
    },
    ["secnet.cap.user"] = {
      name = "User-assigned capability bits",
      type = ftypes.UINT32, mask = 0x000000ff, base = base.HEX
    },
    ["secnet.mtu"] = {
      name = "Sender's requested MTU", type = ftypes.UINT16, base = base.DEC
    },
    ["secnet.kx.sndnonce"] = {
      name = "Sender's nonce", type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.kx.rcvnonce"] = {
      name = "Recipient's nonce", type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.kx.transform"] = {
      name = "Selected bulk-crypto transform", type = ftypes.UINT8,
      base = base.DEC, tab = capmap.transform
    },
    ["secnet.kx.dhval"] = {
      name = "Sender's public Diffie--Hellman value", type = ftypes.NONE
    },
    ["secnet.kx.dhval.len"] = {
      name = "Sender's public Diffie--Hellman length",
      type = ftypes.UINT16, base = base.DEC
    },
    ["secnet.kx.dhval.text"] = {
      name = "Sender's public Diffie--Hellman text", type = ftypes.STRING,
      base = base.ASCII
    },
    ["secnet.kx.sig"] = {
      name = "Sender's signature", type = ftypes.NONE
    },
    ["secnet.kx.sig.len"] = {
      name = "Sender's signature length",
      type = ftypes.UINT16, base = base.DEC
    },
    ["secnet.kx.sig.text"] = {
      name = "Sender's signature text", type = ftypes.STRING,
      base = base.ASCII
    },
    ["secnet.ciphertext"] = {
      name = "Encrypted data", type = ftypes.NONE
    },
    ["secnet.ciphertext.unknown"] = {
      name = "Ciphertext with unknown structure",
      type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.ciphertext.iv"] = {
      name = "Initialization vector", type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.ciphertext.sequence"] = {
      name = "Sequence number", type = ftypes.UINT32, base = base.DEC
    },
    ["secnet.ciphertext.payload"] = {
      name = "Encrypted payload", type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.ciphertext.tag"] = {
      name = "Authentication tag", type = ftypes.BYTES, base = base.SPACE
    },
    ["secnet.wtf"] = {
      name = "Unexpected trailing data",
      type = ftypes.BYTES, base = base.SPACE
    }
  }

  -- Add the remaining capability fields.  Calculate the unassigned mask
  -- based on the assigned bits.
  local unasgn = 0x7fff7f00
  for i, v in pairs(CAPTAB) do
    local flag = bit.lshift(1, i)
    ftab["secnet.cap." .. v.name] = {
      name = v.desc, type = ftypes.BOOLEAN,
      mask = flag, base = 32
    }
    unasgn = bit.band(unasgn, bit.bnot(flag))
  end
  ftab["secnet.cap.unassigned"] = {
    name = "Unassigned capability bits",
    type = ftypes.UINT32, mask = unasgn, base = base.HEX
  }

  -- Convert this table into the protocol fields, and populate `PF'.
  local ff = { }
  local i = 1

  -- Figure out whether we can use `none' fields (see below).
  local use_none_p = rawget(ProtoField, 'none') ~= nil
  for abbr, args in pairs(ftab) do

    -- An annoying hack.  Older versions of Wireshark don't allow setting
    -- fields with type `none', which is a shame because they're ideal as
    -- internal tree nodes.
    ty = args.type
    b = args.base
    if ty == ftypes.NONE then
      if use_none_p then
	b = base.NONE
      else
	ty = ftypes.BYTES
	b = base.SPACE
      end
    end

    -- Go make the field.
    local f = ProtoField.new(args.name, abbr, ty,
			     args.tab, b, args.mask, args.descr)
    PF[abbr] = f
    ff[i] = f; i = i + 1
  end
  secnet.fields = PF

  -- Make readable fields corresponding to especially interesting protocol
  -- fields.
  for abbr, args in pairs(ftab) do
    if args.field then F[abbr] = Field.new(abbr) end
  end
end

-----------------------------------------------------------------------------
--- The main dissector.

function secnet.dissector(buf, pinfo, tree)

  -- Fill in the obvious stuff.
  pinfo.cols.protocol = "Secnet"

  local sz = buf:reported_length_remaining()
  local sub = tree:add(secnet, buf(0, sz), "Secnet packet")
  local p = 12

  -- Decode the message header.
  hdr = sub:add(PF["secnet.hdr"], buf(0, 12))
  local rcvix = buf(0, 4):uint(); hdr:add(PF["secnet.hdr.rcvix"], buf(0, 4))
  local sndix = buf(4, 4):uint(); hdr:add(PF["secnet.hdr.sndix"], buf(4, 4))
  local label = buf(8, 4):uint()
  hdr:add(PF["secnet.hdr.label"], buf(8, 4), label,
	  string.format("Message label (major = 0x%04x, minor = 0x%04x)",
			msgmajor(label), msgminor(label)))
  local st = { pinfo = pinfo, label = label, rcvix = rcvix, sndix = sndix  }
  local info = PKTINFO[label]

  -- Dispatch using the master protocol table.
  if info == nil then
    pinfo.cols.info = string.format("Unknown message label 0x%08x", label)
  else
    pinfo.cols.info = info.info
    p = dissect_sequence(info.dissect, st, buf, sub, p, sz)
  end

  -- Invoke the hook if necessary.
  if not pinfo.visited and info.hook ~= nil then info.hook(st) end

  -- Return the final position we reached.
  return p
end

-- We're done.  Register the dissector.
DissectorTable.get("udp.port"):add(410, secnet)

-------- That's all, folks --------------------------------------------------
