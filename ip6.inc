#TRUSTED 304aa08ca9e3b16e907d1b71ccfdddd9aab7a78a9bf2e3c498f30732f7f081b06fd32f8c81d8a62fea130099b9ca2bb23b2ac31a68752d7d9f47577cdff4dd3d9d32d0af9340868e6156531e379ca894f2088837db33cbd39713aaf104c30beabc41a604881c34d4dd1f11caa49f5ddd17ae9019f0d8d25f8984a2c8fd304c5bbfb5282ddf64cd46ebdf02dc8976e105f82682d57db64cb65466ad82771cdb7a92b9840cc3e3c4d9a731a1b067916c58ba35cadd160a79e92d37aacc15877b545b5402e5ceb9a32e04c091e06caf6f7df017797cf83bc3d30a1bdd8ad98b550c2e7a6b839e70e774509615bf59d28ef790124ebf42d12a00d231a2ede1b5605eb5e0ac52df2b6c2a0b0c3342e6f39cb1f8a06ba65690a8d74836fd4d571c6cabab2a219c6bdf54525d2296a36a0f81c335a38841c5cf50fe4dd965982f316f7668ebc511f6c206489b776348aac58a6207f37dfc9a13745ca49558820271d6e6aa597d5c1320376df08bb7fb65d2f576ce062d28363d2dbce33f19020a0a668b8196211534ce95160e720bf3939845be0c0525d035bd289206af4ccebb0076b403cf64dc1c9e9db50a50f8150799a8a35b0c36e740f440149698478c82b6494c5d50ce055a1d62a99413cdb10bcaaabd1ba9eb24b15f7d59b69ffc0ac2a6eb1d925b543b4f72a9600783cb5cb3cd05642151f37142875c288344e721e40e599c
#TRUST-RSA-SHA256 9dd038f883ad8a5306cf550a21955fe3b5338133aed588ca7f0ee76a7eb235436565ed9df7dd8a41ca024cb14ed0ecb990a52329c9d83090e603c03522e46b837e3f0310d290444571557d1d3e0382868e91e78ba7096bc4de98834165a0105a6b67124700d74946ad1f4aabfed798262f9e59466cd08198cd0869a28b3e5eb6938d9bb010f4ecbc47db69ce29a904f60aa282cad163c01ce8f63422ed9e8bd6e05d08a8f079d5de423538b9ac51fe2541656d4f2818b78640ca354f8c529302db088b6f2e6d7bf8ad1b263cbc15c9fa943a80d41365161dae7ea51263b1ccea9f0323a0800ee59b0441b32eb39acab301064433820081b99145405aff46cd08239aa530514582be284a3c0f991ec55c33e15d7d9d647af2abf840709fc7aa5e71eda16a6fbb074ad860073f6a9c11e622f764b2356560cd76e32921599eb835dc22f8fc7035accc6be91073cc91758908adee14a6497c435009eaea1d5b737da132db446afa210b2d1af6b4688d842986edbf5bef785b795644e9e49667a0cda25db8752f0e5885b4a3c539727dcae39b8528ad006945d31279f87442c1166ad69795f2c489e681d242f25cf131c447f9e2cbffdaf87854359f262f108025cc0ae8094dcd8c1be651d5fe9fd148275ded7d27c6d673e0a088a39e84e2f5e94372a3f3b26d18a0f3633a283ff25d3096866258fe9f9723f307acbb22b15465ca
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
#
# Revision: 1.2

#----------------------------------------------------------------------------#
# IP									     #
#----------------------------------------------------------------------------#

include("byte_func.inc");
include("compat_shared.inc");
include('debug.inc');
include('ip.inc');

#
# Definition of the IP structure
#

var ip6_sizes = make_array(
		"ip6_vfc",  8,
		"ip6_flow",   24,
		"ip6_plen",   16,
		"ip6_nxt",     8,
		"ip6_hlim",    8,
		"ip6_src",128,
		"ip6_dst",128);

var ip6_struct = make_list("ip6_vfc", 
		      "ip6_class", 
		      "ip6_flow", 
		      "ip6_plen", 
		      "ip6_nxt", 
		      "ip6_hlim", 
		      "ip6_src", 
		      "ip6_dst");





#
# Set any IP element
#

function ip6_set(ip6, ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var head,  t;
 local_var ret;

 if ( ip6["type"] != "ip6" )
	return ip6;

 ip6 = ip6["data"];
 
 if ( ! isnull(ip6_vfc) )  ip6["ip6_vfc"] = ip6_vfc;
 if ( ! isnull(ip6_flow) ) ip6["ip6_flow"]    = ip6_flow;
 if ( ! isnull(ip6_plen) ) ip6["ip6_plen"]    = ip6_plen;
 if ( ! isnull(ip6_nxt) )  ip6["ip6_nxt"]     = ip6_nxt;
 if ( ! isnull(ip6_hlim) )  ip6["ip6_hlim"]     = ip6_hlim;
 if ( ! isnull(ip6_src) )  ip6["ip6_src"]     = ip6_src;
 if ( ! isnull(ip6_dst) )  ip6["ip6_dst"]     = ip6_dst;

 ret["data"] = ip6;
 ret["type"] = "ip6";
 return ret;
} 


#
# Create a fresh new packet, with useful default values
#
function ip6(ip6_vfc, ip6_flow, ip6_plen, ip6_nxt, ip6_hlim, ip6_src, ip6_dst)
{
 local_var empty;
 if ( isnull(ip6_vfc) )  ip6_vfc   = 6 << 4;
 if ( isnull(ip6_flow) ) ip6_flow = 0;
 if ( isnull(ip6_plen) ) ip6_plen = 0;
 if ( isnull(ip6_nxt) ) ip6_nxt = IPPROTO_TCP;
 if ( isnull(ip6_hlim) ) ip6_hlim = 64;
 if ( isnull(ip6_src ) ) ip6_src = this_host_raw();
 if ( isnull(ip6_dst ) ) ip6_dst = get_host_raw_ip();

 empty["type"] = "ip6";
 empty["data"] = NULL;

 return ip6_set(ip6:empty,
		ip6_vfc:ip6_vfc,
		ip6_flow:ip6_flow,
		ip6_plen:ip6_plen,
		ip6_nxt:ip6_nxt,
		ip6_hlim:ip6_hlim,
		ip6_src:ip6_src,
		ip6_dst:ip6_dst);
}



#
# Get any item in our IP packet
#
function ip6_get(ip6, element)
{
 local_var t, l, ret;
 if ( isnull(ip6) || ip6["type"] != "ip6" )
 {
  display("ip6_get: invalid 'ip6' argument\n");
  return NULL;
 }
 ip6 = ip6["data"];
 return ip6[element];
}




#
# Transforms an IPv6 structure into a blob which is suitable to be
# sent over the network
#
function mkip6()
{
 local_var item, ret, n, b, ip6;

 ip6 = _FCT_ANON_ARGS[0];
 
 if ( ip6["type"] != "ip6") 
 {
   display("mkip6 : Bad packet type - ", ip6["type"], "\n");
 } 

 ip6 = ip6["data"];

 foreach item ( ip6_struct )
 {
     if ( ip6_sizes[item] == 24 )
	{
	 n = ord(ret[strlen(ret) - 1]);
	 ret = substr(ret, 0, strlen(ret) - 2);
	 ret += mkdword(n << 24 | ip6[item]);
	}
     if ( ip6_sizes[item] == 8 )   ret += mkbyte(ip6[item]);
     if ( ip6_sizes[item] == 16 )  ret += mkword(ip6[item]);
     if ( ip6_sizes[item] == 128 ) ret += ip6[item]; # 128bits -> can only be ip_src or ip_dst
 }

 return ret;
}


function _ip6_x2r()
{
 local_var s;
 s = _FCT_ANON_ARGS[0];
 while ( strlen(s) != 4 ) s = strcat('0', s);

 return hex2raw(s:s);
}

function ip6addr()
{
 local_var ip;
 local_var array;
 local_var i, n;
 local_var ret;
 local_var j;


 ip = _FCT_ANON_ARGS[0];
 array = split(ip, sep:':', keep:FALSE);

 n = max_index(array);
 ret = '';

 for ( i = 0 ; i < n ; i ++ )
 {
  if ( ! strlen(array[i]) )
        {
          for ( j = 0 ; j < 8 - n + 1; j ++ )
                ret += '\x00\x00';
          continue;
        }
  ret += _ip6_x2r(array[i]);
 }

 if ( (strlen(ret) * 8) != 128 ) return NULL;
 return ret;
}

namespace ipv6
{
  ##
  # Validate IPv6 address
  #
  # @param [ip:str] IPv6 address to validate
  # @param [assignable:bool] returns true only for assignable IPv6 addresses if set to true; defaults to false
  #
  # @remark This is by no means a comprehensive check but rather a simple validation check. 
  #
  # @return true if IPv6 address is valid; false otherwise
  ##
  function validate(ip, assignable)
  {
    var blocks, max_index, msg;

    if (empty_or_null(assignable)) assignable = false;

    blocks = split(ip, sep:':', keep:FALSE);

    max_index = max_index(blocks);

    msg = 'IPv6 address ' + ip;

    # Less than 3 blocks
    if (max_index < 3)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg + ' is less than 3 blocks.');
      return false;
    }

    # Cannot be greater than 8 blocks
    if (max_index > 8)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg + ' is more than 8 blocks.');
      return false;
    }

    # Check that all blocks are hexadecimal except the last block which may require special handling 
    for ( var i in blocks )
    {
      if (blocks[i] !~ '^[0-9a-f]{0,4}$')
      {
        # Last block may need special handling
        if (i+1 == max_index)
        {
          # Allow numerical scoped IDs (e.g. fec0:2:2:0:8dcd:c54:c0ef:7e76%1) 
          if (blocks[i] =~ '^[0-9a-f]{0,4}%[0-9]+$') continue;

          # Allow IPv4-mapped IPv6 address (e.g. ::ffff:192.168.139.50)
          #  Conversion is done upstream
          if (ipv4::validate(ip:blocks[i], assignable:assignable)) continue;
        }

        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:strcat(msg + ' contains an invalid block: ', blocks[i]));
        return false;
      }
    }

    # Below is just a start, more unassignable IPv6 address ranges exist
    if (assignable)
    {
      # Unassigned address range
      if (ip == '::')
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg + ' is in the unassigned address range.');
        return false;
      }

      # Loopback address range
      if (ip =~ '^[0:]+[01]$')
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:msg + ' is in the loopback address range.');
        return false;
      }
    }

    # Valid IPv6 address
    return true;
  }
}
