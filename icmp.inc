#TRUSTED 449e2fb6987b58428aeda8fa30eacbea7e2b5986a7fc290802abd3351d178a7a4268d44087500e2f6b45e587fb38271863c8c726f39f97ccc071a0d9ebf935e5782fb14cb2baec48c108242bdda1645cdc38cbd9992ca941e2fec86fc6539bca0bdd840cf4a406742e48a58f3420cdbeb96b9c7617257569cc036c751f24a6a9bf7fd67c7e1cd790d6a44e3ba160352234572012e637f2820fbdeb11a9bd57bd20ad6b4adb8b9ac6d11e9d5e18fa87c2dae5270e5b3e1f71e47b365cb21042d8919b926564b283cef538441c3112c7bf6d493013b424a5698f128ed230287c559e4b4522139d3bca12fe2d1369c813b1d29a9e123ce901881de4f980a6050b58c2d519cfa0072b51818e1ba1e2bf8f1e48cb1a25599693b47fc49095b35a3f35b250de1c0ce3f98412693fdb0a7ec0e06b5b71ffea6e7221e455fdbdab61fef9625c6b3f764013edd252a641d3f38c127cae3d3c39e6a12ff6025ffad80d6ea05548568b04e6e678595c7680d33b8cfca6dcb90d17dac3a5584941d2bb4390d7ab66af52b9ae2e95d06f17d6e4f1aa16326a5d9559844f33a8d40c7666559a684eb06a27e522e0dc8fe4356f9053aeb5ba8444809bdf0623f5f9b9e3f758fd4a281b7cb58eb6ba869b5563193bd68a9b0906a8908786d90bd14198122a1bad6b2164ad82fd43df41daf1e9c1d3bb3ef49a13405224417f19213130ecb8838a13
#
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.4

include("raw.inc");
include("byte_func.inc");

#-------------------------------------------------------------------------#
# ICMP                                                                    #
#-------------------------------------------------------------------------#

var ICMPTYPE_UNREACHABLE = 3;
var ICMPCODE_NET_UNREACH  = 0;
var ICMPCODE_HOST_UNREACH  = 1;
var ICMPCODE_PROTO_UNREACH  = 2;
var ICMPCODE_PORT_UNREACH  = 3;
var ICMPCODE_FRAG_NEEDED  = 4;
var ICMPCODE_SOURCE_ROUTE  = 5;

var ICMPTYPE_TIME_EXCEEDED = 3;
var ICMPTYPE_TTL_EXCEEDED = 0;
var ICMPTYPE_FRAG_REASS = 1;

var ICMPTYPE_PING = 8;
var ICMPTYPE_PONG = 0;

var ICMP6TYPE_PING = 128;
var ICMP6TYPE_PONG = 129;

# TBD

var icmp_sizes = make_array(
	"ih_type",	8,
	"ih_code", 	8,
	"ih_sum",	16,
	"ih_id",	16,
	"ih_seq",	16,
	"ih_data",	-8,
	"ih_gw_addr",	32,
	"ih_orig_ts",	32,
	"ih_rec_ts",	32,
	"ih_trans_ts",	32,
	"ih_ptr",	8,
	"ih_orig_pkt",	-8 );

var icmp_offsets = make_array(
	"ih_type",	0,
	"ih_code",	8,
	"ih_sum",	16,
	"ih_id",	32,
	"ih_seq",	48,
	"ih_data",	64,
	"ih_gw_addr",	32,
	"ih_orig_ts",	64,
	"ih_rec_ts",	96,
	"ih_trans_ts",	128,
	"ih_ptr",	32,
	"ih_orig_pkt",	64 );

function icmp_checksum(icmp, ip, payload)
{
 local_var	icmp0, icmp_r, ret,pseudo;

 if ( (ip["type"] != "ip" && ip["type"] != "ip6") || icmp["type"] != "icmp" )
 {
	display("icmp_checksum: Bad IP argument\n");
	return NULL;
 }

 icmp0 = icmp;
 icmp0["ih_sum"] = 0;
 icmp0["ih_data"] = payload;
 icmp_r = mkicmp(icmp0);
 if (ip["type"] == "ip")
 {
   pseudo = icmp_r;
 }
 else if ( ip["type"] == "ip6" )
 {
   ip = ip["data"];
   pseudo = ip["ip6_src"] + 		
           ip["ip6_dst"] + 		
           '\0\0' + 			
           mkword(strlen(icmp_r)) + 	
           '\0\0\0' + 			
           mkbyte(58) +    
           icmp_r;
 }
 ret = inet_sum(pseudo);
 return ret;
}
 
# To be completed
function icmp_set(icmp, ih_type, ih_code, ih_sum, ih_seq, ih_id)
{
 local_var head, tail, ret, t;

 if ( isnull(icmp) )
 {
  display("set_icmp: NULL ICMP packet\n");
  return NULL;
 }

 if ( icmp["type"] != "icmp" )
  {
	display("set_icmp: bad packet type\n");
	return icmp;
	}

 icmp = icmp["data"];

 if ( ! isnull(ih_type) ) icmp["ih_type"] = ih_type;
 if ( ! isnull(ih_code) ) icmp["ih_code"] = ih_code;
 if ( ! isnull(ih_sum) ) icmp["ih_sum"] = ih_sum;
 if ( ! isnull(ih_seq) ) icmp["ih_seq"] = ih_seq;
 if ( ! isnull(ih_id) ) icmp["ih_id"] = ih_id;

# TBD
 ret["type"] = "icmp";
 ret["data"] = icmp;

 return ret;
}


function icmp(ih_type, ih_code, ih_sum, ih_seq, ih_id)
{
 local_var empty;
 # if ( isnull(ih_seq) ) ih_seq = rand() % 0x7fffffff;
 # TBD
 empty["type"] = "icmp";
 empty["data"] = NULL;
 if ( isnull(ih_id) ) ih_id = rand() % 65534 + 1;
 
 return icmp_set(icmp:empty,
	 	ih_type: ih_type, 
		ih_code: ih_code,
		ih_sum: ih_sum, 
		ih_seq: ih_seq,
		ih_id:  ih_id);
}


function icmp_get(icmp, element)
{
 if ( isnull(icmp) || icmp["type"] != "icmp") 
 {
  display("icmp_get: Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 return icmp[element];
}

function mkicmp()
{
 local_var icmp, ret, item,n,b, l;
 local_var	off, sz, blob;

 icmp = _FCT_ANON_ARGS[0];
 if ( icmp["type"] != "icmp" )
 {
  display("mkicmp(): Bad packet type - ", icmp["type"], "\n");
  return NULL;
 }

 icmp = icmp["data"];
 ret =  '\0\0\0\0\0\0\0\0';
 foreach item (keys(icmp_sizes))
 {
   if (isnull(icmp[item])) continue;

   sz = icmp_sizes[item] / 8;
   off = icmp_offsets[item] / 8;

   if ( icmp_sizes[item] == 8 )		blob = mkbyte(icmp[item]);
   else if ( icmp_sizes[item] == 16 )	blob = mkword(icmp[item]);
   else if ( icmp_sizes[item] == 32 )	blob = mkdword(icmp[item]);

   if (off == 0)
     b = '';
   else
   {
     b =  substr(ret, 0, off -1);
     l = strlen(b);
     if (l < off - 1) b = strcat(b, crap(data: '\0', length: off -l - 1));
   }
   if (  sz > 0) 
     ret = strcat(b, blob, substr(ret, off + sz) );
   else	# Variable size
     ret = strcat( b, icmp[item]);
 }
 return ret;
}

