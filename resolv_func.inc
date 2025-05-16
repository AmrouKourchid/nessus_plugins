#TRUSTED b145fd6703bfa90163fb1302c7f7033c9539a609e515703f8b0f28404eea869b874a84afef2403973cecf3159e7edb41599103464c3ee5cf50be59006e26cbc0bea5558de2fd51aad99c1b2e9dc37a427af5cf2f38fd65004505383bbf85a63b9c20cf75d599b9ef4cdfeae4b5a0746a4bb5e040698d701b34ef7a2de2fa464aefad070329445154b94ad12c4b695584cd1b870c262a42b2a728e2589dbfed173031411e76d4b4a30d5416708ac520724f2bbc9ba13c5ee79633749eed1d16dc021364ffbd1689866d08a22904bd7e9129898b51e809acbefa7c88b2995832798828b8d0891f29ed7e2a5633f864c5e2bf32fedd779812ed94abbf41eb95e9056bb34282e04917ed63aa9e5337a6ab2a8aff9813cee02fa585e479c3547285cfd9b0a76f7f302e7e58c8136dd817fe1fe5a890295c5857d2adaddc2e0bfccdc5ec020b97aee46aacda897d6d6a562f3af3e874184ca3af46641adc2502af0d57853f2b5eb2b6ad24ae75e146122e75b9105ecc4b7b5992bec57b29a4edd6625b631ba257df3af8db71f2854afa5b22496c0cfb70078957a8a46fc0406db788cc9c77fa1ed8416bb1265cc41093d4a1ffddcaa7b10c666f43ad7119ba2f949c6d13c8f7ba74ceba00d1f29e22326d2933746ba5921c8a89a22db06732cd81dd4ecbc2ddf3b1285236dcbf06e3d0f7ec1c752ea225515823a5a8be0410945061ce
#TRUST-RSA-SHA256 08f89bc5431ad7ae3c9775a87acd549eff43bef5798b589400c3175164f1d6698be235d7933c349a53e98e6bcd4171cccac1a12ef4c8b83b3924f1fa4f3d8ddc38da41ed587843cb489e4227cd4c60e7913173fe3d517cf5c97079c1b48882d1959482e49bf3c3f8d694f603f4e23f8a4ac630d0dfb0161ad0fce403781800bb5de0e2f2e05e5779b63aa32061f0996a53f91e770bb7889174153ccfc9c0b57b79cef3b55dcf2609feab52e4c84b5e02e0a48a570c19aa56ec84a6c5208fea02b6d3d3356ef989c58c3c91530f82207f6b88f33bf56ec1dde298d1d32c948c297de4cd9c41212baa970e08ec451444f23176f30c62c03f4f2909a379d032a039424dfd9c3f73566a89e9567ea2c08b2999720610866262ca076b9b0447f53b637118bb74eaa7606bec976e7b8e0e0020c957bebf04ecddf1bf3d422dd82d3e399e132c7df966c192e1a0f50bb54d26bbca20fa0f573c68b5faf0b016802d1c0309101cb1629f22d1ea66eac2f4500664e01b7de92e41d8a8c7af8c8c83945b22667fb6a6467377cb9a30b051f2f6f861eaeefdfe526f4607ba681a57b72fcd10b668cf6438b49b1da12bf966964711417e9e7163f1f789dbf01bf0762bc048bc84b35b6767d305d9fe42ab97b7d49aede436da3142f72513fb7449620e7651f12708ad13d4c4e328128ac5613dd4b2a1f4486d7ce96f449a2d071ebc11316d81
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# resolv_func.inc
#
# Revision: 1.22
###

include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");

##
# Check if the given ``name`` is an IP.
#
# @param [name:string] The string to check for an IP pattern.
#
# @return [boolean] TRUE if ``name`` is an IP, FALSE otherwise.
#
# @remark For IPv6 the function only checks if the string contains a semi-colon (this is not ideal).
##
function is_host_ip(name)
{
 if (":" >< name || preg(string:name, pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$") )
   return TRUE;

 return FALSE;
}

##
# Check if argument is a valid FQDN value.
#
# @param [fqdn:string] value to validate as a FQDN
#
# @return [boolean] true if a valid; false if not valid.
##
function valid_fqdn(fqdn)
{ 
  if (empty_or_null(fqdn)
      || is_host_ip(name:fqdn)
      || fqdn !~ "^[A-Za-z0-9_-]+(([._-])[A-Za-z0-9]+)*\.[A-Za-z][A-Za-z0-9]{1,}$"
      || is_fqdn_blacklisted(fqdn:fqdn)
     )
    return false;

  return true;
}

##
# Check if FQDN is blacklisted such as catch-all FQDNs
#
# @param [fqdn:string] FQDN to check if blacklisted
#
# @return [boolean] true if blacklisted; false if not
##
function is_fqdn_blacklisted(fqdn)
{
  var blacklisted_fqdns, blacklisted_fqdn;

  blacklisted_fqdns = [
    "^unallocated\.barefruit\.co\.uk$",
    "deploy\.static\.akamaitechnologies\.com$",
  ];

  foreach blacklisted_fqdn (blacklisted_fqdns)
  {
    if (fqdn =~ blacklisted_fqdn)
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "The FQDN is blacklisted.",
        msg_details: {
          "fqdn": {"lvl": 2, "value": fqdn}});
      return true;
    }
  }

  return false;
}

##
# Resolves the given FQDN.
#
# @param [name:string] The IP or FQDN to resolve.
# @param [ipv6:boolean] Set to TRUE to resolve FQDN to its IPv6 (optional, default to FALSE).
# @param [fqdn:boolean] Set to TRUE to make sure ``name`` is an FQDN, and append it a '.'.
#
# @return [list] A list of resolved IP addresses.
##
function fqdn_resolv(name, ipv6, fqdn)
{
  local_var len, resolv, msg, log_name;

  # Check to make sure we are not trying to resolve an IP
  if ( is_host_ip(name:name) ) return make_list(name);

  # Adds a "." at the end of the name to make sure it is a FQDN
  if ( fqdn )
  {
   len = strlen(name);
   if ( len > 0 && name[len-1] != '.' )
     name = name + ".";
  }

  resolv = resolv(name:name, ipv6:ipv6);

  if(get_kb_item("global_settings/enable_plugin_debugging"))
  {
    msg = '[fqdn_resolv] Resolving the IP for the following FQDN :\n' +
          '\tName : ' + name + '\n' +
          '\tIP : ' + obj_rep(resolv) + '\n';

    log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
    dbg::detailed_log(name: log_name, lvl: 2, src: FUNCTION_NAME, msg: msg);
  }

  return resolv;
}

##
# Compare two lists of IP addresses to see if they have one IP address in common.
#
# @param [a:list] The first list of IP addresses.
# @param [b:list] The second list of IP addresses.
#
# @return [boolean] TRUE if a common IP address if found, FALSE otherwise.
##
function cmp_addr_v(a, b)
{
  local_var am, bm, ai, bi, msg, log_name;
  log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";

  am = max_index(a);
  bm = max_index(b);

  for (ai = 0; ai < am; ai ++)
  {
    for (bi = 0; bi < bm; bi ++)
    {
      dbg::detailed_log(
        name: log_name,
        lvl: 3,
        src: FUNCTION_NAME,
        msg: "Comparing the following two IPs",
        msg_details:{
          "IP 1": {"lvl":3, "value":a[ai]},
          "IP 2": {"lvl":3, "value":b[bi]}});

      if (a[ai] == b[bi])
        return 1;
    }
  }
  return 0;
}

global_var _target_ip_resolv, _target_name_resolv;

# If b=NULL, compare a with the target
##
# Compare two IPs/FQDNs and determine if they are pointing to the same host.
#
# @param [a:string] The first IP address or FQDN.
# @param [b:list] The second IP address or FQDN.
# @param [fqdn:boolean] Set to TRUE if some of the other arguments are FQDNs.
#
# @remark If ``b`` is left NULL, ``a`` is compared to the target.
#
# @return [boolean] TRUE if the hosts are the same, FALSE otherwise.
##
function is_same_host(a, b, fqdn)
{
  local_var v1, v2, b1, b2, ipv6, msg, log_name;
  log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
  dbg::detailed_log(
    name: log_name,
    lvl: 2,
    src: FUNCTION_NAME,
    msg: "Comparing the following two hosts",
    msg_details:{
      "Host 1": {"lvl":2, "value":a},
      "Host 2": {"lvl":2, "value":b}});

  if (a == b) return 1;

  if (isnull(b))
  {
    if (isnull(a))
    {
      display("ERR: is_same_host: missing arguments 'a' & 'b'\n");
      return NULL;
    }
    b1 = get_host_ip();
    b2 = get_host_name();
    dbg::detailed_log(
      name: log_name,
      lvl: 2,
      src: FUNCTION_NAME,
      msg: "We got the following when getting the host information for comparison",
      msg_details:{
        "Host IP": {"lvl":2, "value":b1},
        "Host Name": {"lvl":2, "value":b2}});

    if (a == b1 || tolower(a) == tolower(b2)) return 1;
    if (! defined_func("resolv")) return 0;

    if (isnull(_target_ip_resolv))
    {
      _target_ip_resolv = fqdn_resolv(name: b1, ipv6: TARGET_IS_IPV6, fqdn: FALSE);
      if (isnull(_target_ip_resolv)) return NULL;
    }
    v2 = fqdn_resolv(name: a, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
    if (isnull(v2)) return NULL;
    if (cmp_addr_v(a: _target_ip_resolv, b: v2)) return 1;

    if (b1 != b2)
    {
      if (isnull(_target_name_resolv))
      {
        _target_name_resolv = fqdn_resolv(name: b2, ipv6: TARGET_IS_IPV6, fqdn: fqdn);
        if (isnull(_target_name_resolv)) return NULL;
      }
      if (cmp_addr_v(a: _target_name_resolv, b: v2)) return 1;
    }

    return 0;
  }

  if (! defined_func("resolv")) return 0;

  for (ipv6 = 0; ipv6 <= 1; ipv6 ++)
  {
    v1 = fqdn_resolv(name: a, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v1)) continue;
    v2 = fqdn_resolv(name: b, ipv6: ipv6, fqdn: fqdn);
    if (isnull(v2)) continue;

    if (cmp_addr_v(a: v1, b: v2)) return 1;
  }

  return 0;
}

##
# Determine FQDN to use.
#
# @return FQDN string if successful,
#         NULL if not (this should not happen)
#
# @remark Multiple FQDNs can be assigned to a host but we want to give priority to
#         FQDNs specified as the target over rDNS lookup.
##
function determine_fqdn() 
{
  local_var fqdn;

  # Function was already called
  fqdn = get_kb_item("Host/FQDN/tag");
  if (!empty_or_null(fqdn))
    return fqdn;

  # rDNS lookup only on IP addresses otherwise return specified FQDN but not hostname
  if (defined_func("get_host_name") && !get_kb_item("DNS/invalid_hostname"))
  {
    fqdn = get_host_name();
    if (valid_fqdn(fqdn:fqdn))
    {
      # Determine if return value is FQDN by simply checking that it resolves 
      if (!empty_or_null(fqdn_resolv(name:fqdn, ipv6:TARGET_IS_IPV6, fqdn:TRUE)))
      {
        set_kb_item(name:"Host/FQDN/tag", value:fqdn);
        set_kb_item(name:"Host/FQDN/src", value:"get_host_name");

        return fqdn;
      }
    }
  }

  # rDNS lookup on hostname
  if (defined_func("get_host_fqdn"))
  {
    fqdn = get_host_fqdn();
    if (valid_fqdn(fqdn:fqdn))
    {
      set_kb_item(name:"Host/FQDN/tag", value:fqdn);
      set_kb_item(name:"Host/FQDN/src", value:"get_host_fqdn");

      return fqdn;
    }
  }

  # Try using the hostname in the kb. We will need to verify via resolving
  # This may not be a fqdn
  var hostname = get_kb_item('Host/hostname');
  if (valid_fqdn(fqdn:hostname))
  {
    # check that the hostname resolves to the same ip address
    var resolved_ips = fqdn_resolv(name:hostname, ipv6:TARGET_IS_IPV6, fqdn:TRUE);
    if (!empty_or_null(resolved_ips)) #ips is a list
    {
      var target_ip = [get_host_ip()]; #put this in a list for ease of use in cmp_addr_v
      if(cmp_addr_v(a: resolved_ips, b: target_ip))
      {
        set_kb_item(name:"Host/FQDN/tag", value:hostname);
        set_kb_item(name:"Host/FQDN/src", value:"Host/hostname");
        return hostname;
      }
    }
  }

  return NULL;
}

##
# Sets 'host-ip' and 'host-fqdn' tags for another host
#
# @param [host:string] The host IP/FQDN to set.
#
# @return TRUE if successful; NULL otherwise.
#
# @remark Only sets 'host-fqdn' tag if hostname is specified.
##
function set_host_tags_for_host(host)
{
  var ip_addr, hostname;

  if (empty_or_null(host))
  {
    err_print(FUNCTION_NAME + '(): missing required argument "host"');
    return NULL;
  }

  # Determine IP address
  if (is_host_ip(name:host))
  {
    ip_addr = host;
  }
  else
  {
    hostname = host;

    ip_addr = resolv(name:host);
    ip_addr = ip_addr[0];
  }

  if (empty_or_null(ip_addr))
  {
    return NULL;
  }

  report_xml_tag2(hostname:host, tag:'host-ip', value:ip_addr);
    
  # Only report FQDN if specified
  if (!empty_or_null(hostname))
  {
    report_xml_tag2(hostname:host, tag:'host-fqdn', value:host);
  }

  return TRUE;
}
