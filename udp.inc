#TRUSTED 6ef93bec060beed4f4a6f3807c1af5e372f1cd5c6141fe868253271bc0409b7159a2d1fe7e01233037160559efb6162f4b12af11e6ff02245bb1e4ab5ecbebfda4ec205ebd47ef1b8e1ca7b82506226a3596b6f6403f44553afa7df286164d421dcb5e59e4c74f73d310cdf263656e9a6ac3b89ee62c684970addd8b38eb683048d048cfa7b2c7fbfa57c6e8be4847ce9b968a97acb80db5d586e0c921fb9eda501c86c05eccfa3cd726b188d9bbd942038708bd1bd7cf42347c9fa22899d31396968f2fc6677f0f55704323ef731a97388cc8b91e869e1dcd4e5a0c5007272201324a8ecc70e1e51f41fcda103961e7a33ad530f01a58a408e283a857e50f6c7ad12fd03dd4049e0d11dee2a8bc20eeeddf7a55335136e9d42bfae1b0a42f4c904a0cae41e070baa250f7e1fb67437fed98569a6f00e18feba8af210adb544d89521bfa37426c72083c5749163e82570d794d9c69e938acd67eb51f6c86dc0a0e26b0a433308a5a348e2135bffc85133f59ca55d1473a73810e3363e4c851a8cc12acad9f1893c02640d01407e8da005d6158c0a9a1e3f8d474fac92f9896d095c912c8f52b333e1150bcfd22b3203815f192c526b2439b5c95874b4015571b540b7a6e1b21f85b72cc3cf2e3f013eb857bc2b8a1fa3159e7e01a623b9230d71555f8cdda1623b7651c75961a20a7fb2703194a365c964dba1d3b5bf77598b1
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# Revision: 1.6
#

include("byte_func.inc");
include("raw.inc");

#
# UDP
#

include("byte_func.inc");
include("raw.inc");

# Define a UDP structure
global_var udp_sizes = make_array(
		"uh_sport", 16,
		"uh_dport", 16,
		"uh_ulen",  16,
		"uh_sum",   16);

global_var udp_struct = make_list(
		"uh_sport",
		"uh_dport",
		"uh_ulen",
		"uh_sum");


function udp_checksum(udp, ip, payload)
{
 local_var src, dst, pseudo, udp_r, ret;
 local_var padding;

 if ( ip["type"] != "ip" || udp["type"] != "udp" )
	{
	display("udp_checksum: Bad IP argument\n");
	return NULL;
	}
 ip  = ip["data"];

 
 udp_r = mkudp(udp);
 
 src = ipaddr(ip["ip_src"]);
 dst = ipaddr(ip["ip_dst"]);
 if ( strlen(payload) & 1 == 1 ) padding = raw_string(0);
 else padding = NULL;

 pseudo = src +
	  dst +
	  mkbyte(0) +
	  mkbyte(IPPROTO_UDP) +
	  mkword(strlen(udp_r) + strlen(payload)) + udp_r + payload + padding;

 ret = inet_sum(pseudo);
 return ret;
}

function udp_get(udp, element)
{
 if ( isnull(udp) || udp["type"] != "udp" )
	{
	display("udp_get: Invalid packet\n");
	return NULL;
	}

 udp = udp["data"];
 return udp[element];
}

function udp_set(udp, uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var ret;
 if ( isnull(udp) || udp["type"] != "udp" )
 {
  display("udp_set: Bad packet type\n");
  return NULL;
 }

 udp = udp["data"];
 if ( !isnull(uh_sport) ) udp["uh_sport"] = uh_sport;
 if ( !isnull(uh_dport) ) udp["uh_dport"] = uh_dport;
 if ( !isnull(uh_ulen) ) udp["uh_ulen"] = uh_ulen;
 if ( !isnull(uh_sum) ) udp["uh_sum"] = uh_sum;


 ret["type"] = "udp";
 ret["data"] = udp;
 return ret;
}


function mkudp()
{
 local_var item, ret, n, b, udp;

 udp = _FCT_ANON_ARGS[0];
 
 if ( udp["type"] != "udp") 
 {
   display("mkudp : Bad packet type - ", udp["type"], "\n");
 } 

 udp = udp["data"];

 foreach item ( udp_struct )
 {
     if ( udp_sizes[item] == 16 ) ret += mkword(udp[item]);
     else {
	display("Inconsistent UDP structure\n");
	return NULL;
	}
 }

 return ret;
}


function udp(uh_sport, uh_dport, uh_ulen, uh_sum)
{
 local_var empty;
 if ( isnull(uh_sport) ) uh_sport = 1024;
 if ( isnull(uh_dport) ) uh_dport = 53;
 if ( isnull(uh_ulen ) ) uh_ulen  = 8;
 if ( isnull(uh_sum  ) ) uh_sum   = 0;

 empty["type"] = "udp";
 empty["data"] = NULL;
 return udp_set(udp:empty,
		uh_sport:uh_sport,
		uh_dport:uh_dport,
		uh_ulen: uh_ulen,
		uh_sum : uh_sum);
}

global_var _udp_buf;

##
# Get a single line of text from a UDP socket.
#
# @param length  Maximum number of bytes to receive, passed to recv
# @param socket  UDP socket to read from
# @param timeout Number of seconds to wait for data, passed to recv
#
# @remark This function cannot be used across multiple sockets at the
#         same time, as the buffer is global.
#
# @return A single line of text from the UDP socket.
##
function udp_recv_line(length, socket, timeout)
{
  local_var data, i, line;

  # Sanity check parameters.
  if (isnull(length))
    return NULL;

  if (isnull(socket))
    return NULL;

  # Make sure that there's a line in the buffer.
  while (TRUE)
  {
    # Check if we have a line yet.
    i = stridx(_udp_buf, '\n');
    if (i != -1)
      break;

    # Get new data from the socket.
    data = recv(socket:socket, length:length, timeout:timeout);
    if (isnull(data))
      return NULL;

    _udp_buf += data;
  }

  # Cut a line out of the buffer.
  line = substr(_udp_buf, 0, i);
  _udp_buf = substr(_udp_buf, i + 1);

  return line;
}

##
# Clears the UDP buffer used by [udp_recv_line].
##
function udp_recv_line_reset()
{
  _udp_buf = "";
}
