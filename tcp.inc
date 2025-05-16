#TRUSTED 27f7fb41580445001510d3dfcd0e3e0b64cd46c5dbb8ff9085f12e1afa5e399fa2e2007d4cc8aaebf09cdbc535173aefa201e762b24ae248f5a83d85cfbe4bd41d51a9263ba897c9fb7c295ee1e250d13c52e5a94a5810f1b57aba4dbc7f173274d2d4ec54bd945e9ef1aaeed44a7a74ab5b199c09fe7d67e0d0914890c8ce84caa42fb89be3b559e0c602dbd4e2b146915d066b9ddbee9732f338dfb6c48c421225c448a2bb36132145a1fa2987c8349c862f49386268f7d87fb7bbb73ebcc18261b74e7e4830f5cd000b95842b93b9a02619601f6bb3083181e9979fc668acf2a12b4cdc937d6349c59ef1791c760ace44cc28235659dcffdc9587d597eaf0f1733d84de1b633e12c476c11c93b3a60b6c9e62e4cb49df5012aa7c23a2e40cd0a5fca3e7fc0932540a4f5881d807f20b4dac1d44c69c201133ff1b260a21e83137b1c87ad71d2e0d06419afd0b312124a00cd66e1c1a1bec0e8d8d89658b8409e745d15ee785b25ec9b4a6c0de3d2366872de1fd7de03086967c18fb3d0ea4268c35d28a818a096b39a48f196211027640121ab3a694a8fa2e36b8426be676764a33c95c68904059d8f388a363e4ac978ad8a54f37add42844243fc17dc386a92365d2de94a3b06a897941b1a5c2d6283eaccb57c440e18b2ba1a5a284b86535b3c713e04e5413954d9cff6447bfda6486cc8f98c4f9184c495625138abd96
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
#
#
# Revision: 1.1
#

include("raw.inc");
include("byte_func.inc");

#-------------------------------------------------------------------------#
# TCP                                                                     #
#-------------------------------------------------------------------------#

var tcp_sizes = make_array(
		"th_sport",	16,
		"th_dport", 	16,
		"th_seq",	32,
		"th_ack",	32,
		"th_off",	 4,
		"th_x2",	 4,
		"th_flags",	 8,
		"th_win",	16,
		"th_sum",	16,
		"th_urp",	16);

var tcp_struct = make_list(
		"th_sport",
		"th_dport",
		"th_seq",
		"th_ack",
		"th_off",
		"th_x2",
		"th_flags",
		"th_win",
		"th_sum",
		"th_urp",
		"options");


function tcp_checksum(tcp, ip, payload)
{
 local_var src, dst, pseudo, tcp_r;

 if ( (ip["type"] != "ip" && ip["type"] != "ip6") || tcp["type"] != "tcp" )
	{
	display("tcp_checksum: Bad IP argument\n");
	return NULL;
	}

 tcp_r = mktcp(tcp);
 if ( ip["type"] == "ip") 
 {
  ip = ip["data"];
  src = ipaddr(ip["ip_src"]);
  dst = ipaddr(ip["ip_dst"]);
  pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_TCP) +
	  mkword(strlen(tcp_r) + strlen(payload)) + tcp_r + payload + crap(data:'\0', length:strlen(payload) % 4);
 }
 else if ( ip["type"] == "ip6" )
 {
  ip = ip["data"];
  pseudo = ip["ip6_src"] + 		
           ip["ip6_dst"] + 		
           '\0\0' + 			
           mkword(strlen(tcp_r)) + 	
           '\0\0\0' + 			
           mkbyte(IPPROTO_TCP) +    
           tcp_r +
           payload;

 }

 
 return inet_sum(pseudo);
}


function tcp_set(tcp, th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var head, tail, ret, t;

 if ( isnull(tcp) )
 {
  display("set_tcp: NULL TCP packet\n");
  return NULL;
 }

 if ( tcp["type"] != "tcp" )
  {
	display("set_tcp: bad packet type\n");
	return tcp;
	}

 tcp = tcp["data"];

 if ( ! isnull(th_sport) ) tcp["th_sport"] = th_sport;
 if ( ! isnull(th_dport) ) tcp["th_dport"] = th_dport;
 if ( ! isnull(th_seq)   ) tcp["th_seq"]   = th_seq;
 if ( ! isnull(th_ack)   ) tcp["th_ack"]   = th_ack;
 if ( ! isnull(th_off)   ) tcp["th_off"]   = th_off;
 if ( ! isnull(th_x2)    ) tcp["th_x2"]    = th_x2;
 if ( ! isnull(th_flags) ) tcp["th_flags"] = th_flags;
 if ( ! isnull(th_win) )   tcp["th_win"]   = th_win;
 if ( ! isnull(th_sum) )   tcp["th_sum"]   = th_sum;
 if ( ! isnull(th_urp) )   tcp["th_urp"]   = th_urp;

 ret["type"] = "tcp";
 ret["data"] = tcp;

 return ret;
}


function tcp(th_sport, th_dport, th_seq, th_ack, th_off, th_x2, th_flags, th_win, th_sum, th_urp )
{
 local_var empty;
 if ( isnull(th_sport) ) th_sport = rand() % ( 65535  - 1024 ) + 1024;
 if ( isnull(th_dport) ) th_dport = 80;
 if ( isnull(th_seq) ) th_seq = rand() % 0x7fffffff;
 if ( isnull(th_ack) ) th_ack = 0;
 if ( isnull(th_off) ) th_off = 5;
 if ( isnull(th_x2) )  th_x2  = 0;
 if ( isnull(th_flags))th_flags = TH_SYN;
 if ( isnull(th_win) ) th_win  = 65535;
 if ( isnull(th_urp) ) th_urp  = 0;

 empty["type"] = "tcp";
 empty["data"] = NULL;
 
 return tcp_set(tcp:empty,
	 	th_sport:th_sport,
		th_dport:th_dport,
		th_seq:th_seq,
		th_ack:th_ack,
		th_off:th_off,
		th_x2:th_x2,
		th_flags:th_flags,
		th_win:th_win,
		th_sum:th_sum,
		th_urp:th_urp);
}


function tcp_get(tcp, element)
{
 if ( isnull(tcp) || tcp["type"] != "tcp") 
 {
  display("tcp_get: Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 return tcp[element];
}

function mktcp()
{
 local_var tcp, ret, item,n,b;

 tcp = _FCT_ANON_ARGS[0];
 if ( tcp["type"] != "tcp" )
 {
  display("mktcp(): Bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 tcp = tcp["data"];
 foreach item ( tcp_struct )
 {
  if ( tcp_sizes[item] == 4 ) 
  {
	if ( n == 0 )
	{
	  b = tcp[item];
	  n = 1;
	}
	else 
	{
	  b = b << 4 | tcp[item];
	  ret += mkbyte(b);
	  n = 0;
	}
  }
  else if ( tcp_sizes[item] == 8 )  ret += mkbyte(tcp[item]);
  else if ( tcp_sizes[item] == 16 ) ret += mkword(tcp[item]);
  else if ( tcp_sizes[item] == 32 ) ret += mkdword(tcp[item]);
  else if ( item == "options" )
	{
	  if ( strlen(tcp[item]) % 4 ) tcp[item] += crap(data:mkbyte(0), length:4 - ( strlen(tcp[item]) % 4 ) );
	  ret += tcp[item];
	}
 }
 return ret;
}


function tcp_insert_option(tcp, type, length, data)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }
 
 pkt = tcp["data"];
 pkt["options"] += mkbyte(type);
 if ( ! isnull(length) )
 { 
  pkt["options"] += mkbyte(length);
  pkt["options"] += data;
 }

 pkt["th_off"] = (  20 + strlen(pkt["options"]) ) / 4;
 tcp["data"] = pkt;
 return tcp;
}


function tcp_finish_insert_option(tcp)
{
 local_var pkt;
 if ( isnull(tcp) || tcp["type"] != "tcp" ) 
 { 
  display("tcp_finish_insert_option: bad packet type - ", tcp["type"], "\n");
  return NULL;
 }

 pkt = tcp["data"];
 if ( strlen(pkt["options"]) % 4 )
	pkt["options"] += crap(length:4 - (strlen(pkt["options"]) % 4 ), data:mkbyte(0));

 pkt["th_off"] = 5 + (strlen(pkt["options"]) / 4);
 tcp["data"] = pkt;
 return tcp;
}

