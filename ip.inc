#TRUSTED 8f1ca75d1840ea51eb9bf0d56efa49a350e44d3cdf5c6295963cd63d3740a19df2e455bf2600a3a7943d28e276c7cf16af0613844bd4353d9fc781b37231432254a2c07ac42a547857f5f492c95138c5fead6b0d486e6c1dc4265ab312864c0fcc59fff39c5e83843e21a4670a64818dabcedf04f6922d6ee7b252a33db1b33d70244b8e87ab4089439f2c6d58cb32c2aa306ee905d125269cc8f8e8bc4b7666baa5f65b9669e445434e32ec2b471e8bdb7f6f47e6b401d7c6b5013ad4d0fb9912d419f0be40d88ab1c5432ff5c388a74ac4814719d4ceac120b098173138d8d4bd9cfe918f5b4ff245c6b49a950fd1d0d94e18970f035ef4b63ce76c532ebc0853cd4baf75c8e6d90e7138ebd3e90cf500a256ff7b7f032ebb7406dffcd9ec0f0e42ffd2b9375f65d5507d77ef9a65f433870c03623472f31deaf7f737af5d8c4e3769595dc6970c09f4ba23c3f3f39552890a0a01641ed252c1e7cf9fdb8597f66d1265518be0de7471a18ea34f74ab321f5820a7918a87e7e57a32d521948df20d8a6941a6fd8894103a68bc93275bc007fa6f5ad4d9673d3cc71f530b774b1d572aecdbf26a4fb62b2092d36c4e336ba9965a364de200350bc764635ea4a5717bac06934991ee719b531b93b6fb10265b83f8d789810dc6449d2f61cf50a7704216edec2079c347716e2a6e6a3d43d831d7aa18fa505d401833b5f56749d
#TRUST-RSA-SHA256 9490d2c0e90a8e631644b7e40e5a79be0ecfa92319bc76f88b101b4dbea7cc1f2def2dad1638891f8a1e7bfaf547ef2beb71d3132653492f7bfd184bf9ef6d4137849b32b12025f60b31ff314d2808e14c5f3ea32da1018d712423a70e5da0497a77a776b48ccd2fbef6512f1183c388a41c126fdb639b5583b1e78678e97b0d09b9958dc7a4fe847b427a463f8e001260137254fde4c60b3310d9aa0e91c7fb45bbab5ef2927ae79a2f8dd7de3760bf979a6ff466bb7468f8297d4e869288a614792582ba5c493ba4952b1a6807ee04ddb82b54b82ccfd46126411d6d2e759a02ad7577ea0a9e86f7cfa14ecb93432a8d38e719b15587ea0dc4677d828dc01085ae5f2af904beebeb166c9a667ed1a2fbe76c0c5948985fdd1962676616de63e0966c300aa385d4b5e284580c53dce41739c43ed179cb2d6841d2efbad419921eac46a9d564bdfe130b58392b946bb5d47feec68e73afd12062fe0124386d93256324672951998484525a69041ceb5328c42eafdb6581a5c2d03828aaace6c4f16735250870b2d218fbce0be13d7e8ade626ba0e9a07472067667d91d9df4cc0051b7346b98d58637ea00866a5e1153c5cc9f39a6891d252f1d832163ea0a834a8441ac624c0d66315ef6a5b16d9ca3a0d93d526e63c01f0ec76d9e0e8885c4c9d59eba23e455327fb948c5972f9deb2261e78a9e8a9d3b84658f199ce21c9a
#
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# Revision: 1.2
#
include("compat_shared.inc");
include("byte_func.inc");
include('debug.inc');
include("raw.inc");


#----------------------------------------------------------------------------#
# IP									     #
#----------------------------------------------------------------------------#


#
# Definition of the IP structure
#

var ip_sizes = make_array(
		"ip_v",  4,
		"ip_hl", 4,
		"ip_tos",8,
		"ip_len",16,
		"ip_id", 16,
		"ip_off",16,
		"ip_ttl",8,
		"ip_p",  8,
		"ip_sum",16,
		"ip_src",32,
		"ip_dst",32);

var ip_struct = make_list("ip_v", 
		      "ip_hl", 
		      "ip_tos", 
		      "ip_len", 
		      "ip_id", 
		      "ip_off", 
		      "ip_ttl", 
		      "ip_p", 
		      "ip_sum", 
		      "ip_src", 
		      "ip_dst",
		      "options");



#
# Compute the checksum of an IP packet
#
function ip_csum()
{ 
 local_var p, pk;
 p = _FCT_ANON_ARGS[0];
 if ( isnull(p) || p["type"] != "ip" )
 {
  display("ip_csum: bad type - ", p["type"], "\n");
  return NULL;
 }
 
 pk = mkip(p);
 return inet_sum(pk);
}




#
# Set any IP element
#

function ip_set(ip, ip_hl, ip_v, ip_tos, ip_len, ip_id, ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst, options )
{
 local_var head,  t;
 local_var ret;

 if ( ip["type"] != "ip" )
	return ip;

 ip = ip["data"];
 
 if ( ! isnull(ip_v) )  ip["ip_v"] = ip_v;
 if ( ! isnull(ip_hl) ) ip["ip_hl"] = ip_hl;
 if ( ! isnull(ip_tos)) ip["ip_tos"] = ip_tos;
 if ( ! isnull(ip_len)) ip["ip_len"] = ip_len;
 if ( ! isnull(ip_id))  ip["ip_id"] = ip_id;
 if ( ! isnull(ip_off)) ip["ip_off"] = ip_off;
 if ( ! isnull(ip_ttl)) ip["ip_ttl"] = ip_ttl;
 if ( ! isnull(ip_p))   ip["ip_p"] = ip_p;
 if ( ! isnull(ip_sum)) ip["ip_sum"] = ip_sum;
 if ( ! isnull(ip_src)) ip["ip_src"] = ip_src;
 if ( ! isnull(options))ip["options"] = options;
 if ( ! isnull(ip_dst)) ip["ip_dst"] = ip_dst;


 ret["data"] = ip;
 ret["type"] = "ip";
 return ret;
} 


#
# Create a fresh new packet, with useful default values
#
function ip( ip_hl, ip_v, ip_tos, ip_len, ip_id, ip_off, ip_ttl, ip_p, ip_sum, ip_src, ip_dst, options)
{
 local_var empty;
 if ( isnull(ip_hl) )  ip_hl = 5;
 if ( isnull(ip_v)  )  ip_v  = 4;
 if ( isnull(ip_tos))  ip_tos = 0;
 if ( isnull(ip_len))  ip_len = 20;
 if ( isnull(ip_id ) ) ip_id  = rand() % 65534  + 1;
 if ( isnull(ip_off) ) ip_off = IP_DF;
 if ( isnull(ip_ttl) ) ip_ttl = 128;
 if ( isnull(ip_p)   ) ip_p   = IPPROTO_TCP;

 if ( isnull(ip_src) ) ip_src = compat::this_host();
 if ( isnull(ip_dst) ) ip_dst = get_host_ip();

 empty["type"] = "ip";
 empty["data"] = NULL;

 return ip_set(ip:empty,
	       ip_v:ip_v,
	       ip_hl:ip_hl,
	       ip_tos:ip_tos,
	       ip_len:ip_len,
	       ip_id:ip_id,
	       ip_off:ip_off,
	       ip_ttl:ip_ttl,
	       ip_p:ip_p,
	       ip_sum:ip_sum,
	       ip_src:ip_src,	
	       ip_dst:ip_dst,	
	       options:options);
}



#
# Get any item in our IP packet
#
function ip_get(ip, element)
{
 local_var t, l, ret;
 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_get: invalid 'ip' argument\n");
  return NULL;
 }
 ip = ip["data"];
 return ip[element];
}


#
# Insert an IP option in our packet
#
function ip_insert_option(ip, option)
{
 local_var pkt;

 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_insert_option: invalid 'ip' argument\n");
  return NULL;
 }

 if ( isnull(option) || option["type"] != "ip_option") 
 {
  display("ip_insert_option: invalid 'option' argument\n");
  return NULL;
 }

 pkt = ip["data"];
 pkt["options"] += option["data"];
 ip["data"] = pkt;
 
 return ip;
}

#
# Compute the padding for the ip options and update ip->ip_hl
#
function ip_finish_insert_option()
{
 local_var pkt, ip;
 
 ip = _FCT_ANON_ARGS[0];
 if ( isnull(ip) || ip["type"] != "ip" )
 {
  display("ip_insert_option: invalid 'ip' argument\n");
  return NULL;
 }

 pkt = ip["data"];
 if ( strlen(pkt["options"]) % 4 != 0 )
	pkt["options"] += crap(length: 4 - strlen(pkt["options"]) % 4, data:mkbyte(0)); 

 pkt["ip_hl"] = 5 + strlen(pkt["options"]) / 4;
 ip["data"] = pkt;
 return ip;
}


#
# Create an IP option of type <type>, length <length> and data <data>
#
function ip_option(type, length, data)
{
 local_var ret, opt;
 ret["type"] = "ip_option";
 opt = mkbyte(type);
 if ( !isnull(length) ) 
 {
  opt += mkbyte(length);
  opt += data;
 }
 ret["data"] = opt;
 return ret;
}


#
# Transforms an IP structure into a blob which is suitable to be
# sent over the network
#
function mkip()
{
 local_var item, ret, n, b, ip, opt;

 ip = _FCT_ANON_ARGS[0];
 
 if ( ip["type"] != "ip") 
 {
   display("mkip : Bad packet type - ", ip["type"], "\n");
 } 

 ip = ip["data"];

 foreach item ( ip_struct )
 {
  if ( ip_sizes[item] == 4 ) 
	{
	if ( n == 0 )
		{
		 b = ip[item];
		 n = 1;
		}
 	else 	{
		 b = b << 4 | ip[item];
		 ret += mkbyte(b);
		 n = 0;
		}
	}
  else  {
     if ( ip_sizes[item] == 8 )   ret += mkbyte(ip[item]);
     if ( ip_sizes[item] == 16 ) {
		  if ( RawSendViaOperatingSystem && bsd_byte_ordering() && ! big_endian() && ( item == "ip_off" || item == "ip_len") )
			set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
		  ret += mkword(ip[item]);
		  if ( RawSendViaOperatingSystem && bsd_byte_ordering() && ! big_endian() && ( item == "ip_off" || item == "ip_len") )
			set_byte_order(BYTE_ORDER_BIG_ENDIAN);
     }
     if ( ip_sizes[item] == 32 )  ret += ipaddr(ip[item]); # 32bits -> can only be ip_src or ip_dst
     else if ( item == "options") {
	opt = ip[item];
	if ( strlen(opt) % 4  != 0 ) opt += crap(data:mkbyte(0), length: 4 - (strlen(opt) % 4) );
	ret += opt;
	}
   }
 }

 return ret;
}

namespace ipv4
{
  ##
  # Validate IPv4 address
  #
  # @param [ip:str] IPv4 address to validate
  # @param [assignable:bool] returns true only for assignable IPv4 addresses if set to true; defaults to false
  #
  # @remark There are additional address ranges that can be considered invalid but these are commented out to avoid unintended consequences.
  #
  # @return true if IPv4 address is valid; false otherwise
  ##
  function validate(ip, assignable)
  {
    var msg, octets, octet;

    if (empty_or_null(assignable)) assignable = false;

    msg = 'IPv4 address ' + ip;

    octets = split(ip, sep:'.', keep:FALSE);

    # Must be 4 octets
    if (len(octets) != 4)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg + ' is not 4 octets.');
      return false;
    }

    # Check that all octets are between 0 and 255
    foreach octet (octets)
    {
      if ( !(octet >= 0 && octet <= 255) )
      {
        dbg::detailed_log(
          lvl:1, src:FUNCTION_NAME, msg:strcat(msg, ' contains octet ', octet, ' that is not between 0 and 255.'));
        return false;
      }
    }

    if (assignable)
    {
      # Unassigned address range
      if (octets[0] < 1)
      {
        dbg::detailed_log(
          lvl:1, src:FUNCTION_NAME, msg:strcat(msg, ' contains a first octet ', octets[0],  ' that is less than 1.'));
        return false;
      }

      # Loopback address range
      if (octets[0] == 127)
      {
        dbg::detailed_log(
          lvl:1, src:FUNCTION_NAME, msg:strcat(msg, ' contains a first octet ', octets[0],  ' that is a loopback address.'));
        return false;
      }

      # Link-local address range - TBD: commenting out to avoid side effects
      #if (octets[0] == '169' && octets[1] == '254') return false;

      # Multicast address range - TBD: commenting out to avoid side effects
      #if (octets[0] >= '224' && octets[0] <= '255') return false;
    }

    # Valid IPv4 address
    return true;
  }
}
