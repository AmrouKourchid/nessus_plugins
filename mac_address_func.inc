#TRUSTED 5cdae9ce89bfb077149186c1e1da78609d9ec1190670d3c113a9f260c7881f46f37192466cfb0475cb9277247769b4f532c4f2c180f5bd26453db571db2ec2eca221e77102d2926b0108b7984e81105fcaa47f63cf5cbb580883cd3db56bcbc145bc11d5e2b1a17fbef8f6a54b7a0fa6672017830546ad26539cddc15e3e1e9379639a6d7587dc99131af9ee10a606f1017332c329f09051283b8ed498ea2d3217ff37978d02f8190dcc00a1ffc9bfac345d0a33152a92bad546cb9bce348c5dc824b4184031cab4d0571a2db5023cc2b23d8dae93eb69ce1fe66e0c7d3e0337ade1bb2c112230877c8c776494f7cb8c4b4ceb6f7d1cbe71af8bf94d7ff6dbe70925e5f9d566ffd12a9189071912f9c8a86e327f8c55cbfa3e0292f7a11036b618ce141efbf002a54e69c57c3f980e3dd1b1f2a907c7706d45466692abea3a8c0ef9338a97f1a4b50640a5a64ed8c512010de5c7840de280b93dcc5c07d95160be4d2f18dc19e6156e51db9b361a1221bb96d15b489cfb3218fe90348a026e3696321247e17ed6392b22d7f24f72feab209e80ee73d7d55b974de09e1a0ae80fa82f84f9286c1cea7ffaa6fe9820636a7c16ab376acf63f3323372924d7b03220505130f6b836d43ff5bd969c9745a32b5fb17e33c26b77a9b178f90d164f7410a92bbe713e5d9d178c840f45140196877fcda3470c5eb64b4606d3031efd89f
#TRUST-RSA-SHA256 9f030183c6c3d00ddd560f82384e3693ee5e9594f5d4a1b678c4ed7b8b05c9253dafd5e892ebcf1f0006a5c45a08eaf65959edf1a339514199f62cf17362de9e1c18a0c24880202c8b0104f909066abdd6246dccae316aed855784712a6a3bfccd2511f0291d44488b0435a83fe65018c747d37c5a2697beb4ad52ce51fb12b1910387e2c6d4bbf9f3b87beb9a79b3c564cc596f5346227f642a2f79be50a9ac199c3e9b60ae899ffe6ac72a4f560ed88a6b20bcec9da9e4b475d15d3166e6901455280f6620d550ba5ca3b5bcba098b07914a7098c7ee55edb53aa133965e5371e1c8f08b0b3fe107247498b0159e51be8bdfe61623ead36980fe0880bd845b3c8d56ac796a2df0c4ceb79aa5b07bcf303ffe3fd4b72143c87a0bff0df4299107dc7969522c09027888357a0625f15bac75e89016acbb018ddc31afc63f476deec826052d09f48b3f37c8ffd3b3886fefad35846aead63ac57100cd76a7b713a791fe982c4d617f9c6629fb4cdc8c6ce9d46b8da44fc07f021843589a7f22b9a5dcbd4ee761e1bacaec721b1b8fc5479dc90d1c182df028dda7c76b44b812f54f02854cc93f7703a569329944c35fbe45a26f48caad3d1a1b20f3b615fe5647217d772291c2a194186ee0ab6f320e4b361c1d1bedbf56ff02d6d75097e438f8422589d77ccc309907cfd7ca213501de6193f8f29049827e95d0869f39981437
###
# Functions for collecting and processing MAC addresses.
#
# @license
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# mac_address_func.inc
#
# Revision: 1.20
#
# @NOGPL@
#
###

include("compat_shared.inc");
include('debug.inc');

#pragma static(include)
include('mac_address_classifier.static');
#pragma static(include:false)

global_var CISCO_MAC_RGX    = "[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}";
global_var IFCONFIG_MAC_RGX = "([a-fA-F0-9]{2}[:-]){5}[a-fA-F0-9]{2}";
global_var SOLARIS_MAC_RGX  = "([a-fA-F0-9]{1,2}[:]){5}[a-fA-F0-9]{1,2}";

global_var BLACKLISTED_MACS = make_list(
  '00:00:00:00:00:00', # loopback
  '00:05:9A:3C:78:00', # Cisco IPSec VPN Client
  '00:05:9A:3C:7A:00', # Cisco SSL VPN Client
  '00:09:0F:FE:00:01', # Fortinet
  '00:1C:42:00:00:00', # Parallels
  '00:1C:42:00:00:01', # Parallels
  '00:1C:42:00:00:02', # Parallels
  '00:1C:42:00:00:03', # Parallels
  '00:1C:42:00:00:04', # Parallels
  '00:1C:42:00:00:05', # Parallels
  '00:1C:42:00:00:06', # Parallels
  '00:1C:42:00:00:07', # Parallels
  '00:1C:42:00:00:08', # Parallels
  '00:1C:42:00:00:09', # Parallels
  '00:26:37:BD:39:42', # Samsung Electro Mechanics - PdaNet Adapter
  '00:50:56:C0:00:01', # VMware
  '00:50:56:C0:00:02', # VMware
  '00:50:56:C0:00:03', # VMware
  '00:50:56:C0:00:04', # VMware
  '00:50:56:C0:00:05', # VMware
  '00:50:56:C0:00:06', # VMware
  '00:50:56:C0:00:07', # VMware
  '00:50:56:C0:00:08', # VMware
  '00:50:56:C0:00:09', # VMware
  '00:53:45:00:00:00', # Unknown vendor
  '00:A0:C6:00:00:00', # Qualcomm
  '00:A0:D5:FF:FF:85', # Sierra Wireless WWAN Adapter
  '00:09:0F:09:00:0C', # Fortinet
  '00:09:0F:09:00:08', # Fortinet
  '00:00:00:00:00:14', # Juniper
  '00:10:DB:FF:10:00', # Juniper
  '00:10:DB:FF:10:01', # Juniper
  '00:10:DB:FF:10:02', # Juniper
  '00:10:DB:FF:10:03', # Juniper
  '00:10:DB:FF:10:04', # Juniper
  '00:0B:CA:FE:00:00', # Juniper
  '02:00:00:00:00:04', # Juniper
  '02:00:00:00:00:0A', # Juniper
  '02:00:00:00:00:0B', # Juniper
  '02:00:00:00:00:33', # Juniper
  '02:00:00:01:01:04', # Juniper
  '02:00:00:01:03:04', # Juniper
  '02:00:01:00:00:04', # Juniper
  '02:00:01:01:01:04', # Juniper
  '02:00:01:01:03:04', # Juniper
  '02:00:01:02:01:04', # Juniper
  '02:00:00:02:01:04', # Juniper
  '02:00:02:00:00:04', # Juniper
  '88:A2:5E:0A:DB:82', # Juniper
  'E0:30:F9:77:EB:F5', # Juniper
  'E0:30:F9:77:EB:F6', # Juniper
  'E0:30:F9:77:EB:F7', # Juniper
  'E0:30:F9:77:EB:F8', # Juniper
  'E0:30:F9:77:EB:F9', # Juniper
  'E0:30:F9:77:EB:FA', # Juniper
  'E0:30:F9:77:EB:FB', # Juniper
  'E0:30:F9:77:EB:FC', # Juniper
  'E0:30:F9:77:EB:FD', # Juniper
  'E0:30:F9:77:EB:FE', # Juniper
  'E0:30:F9:77:EB:FF', # Juniper
  'E0:30:F9:77:EB:F4', # Juniper
  'E0:30:F9:77:EB:F6', # Juniper
  'E0:30:F9:77:EC:00', # Juniper
  'E0:30:F9:77:EC:01', # Juniper
  'E0:30:F9:77:EC:02', # Juniper
  'E0:30:F9:77:EC:03', # Juniper
  'E0:30:F9:77:EC:04', # Juniper
  'E0:30:F9:77:EC:A4', # Juniper
  'E0:30:F9:77:EC:A3', # Juniper
  'E0:30:F9:77:EC:A6', # Juniper
  'E8:24:A6:47:9E:81', # Juniper
  'E8:24:A6:47:9E:82', # Juniper
  'E8:24:A6:47:9E:83', # Juniper
  'E8:24:A6:47:9E:84', # Juniper
  'E8:24:A6:47:9E:85', # Juniper
  'E8:24:A6:47:9E:86', # Juniper
  'E8:24:A6:47:9E:87', # Juniper
  'E8:24:A6:47:9E:88', # Juniper
  'E8:24:A6:47:9E:89', # Juniper
  'E8:24:A6:47:9E:8A', # Juniper
  'E8:24:A6:47:9E:8B', # Juniper
  'E8:24:A6:47:9E:8C', # Juniper
  'E8:24:A6:47:9E:8D', # Juniper
  'E8:24:A6:47:9E:8E', # Juniper
  'E8:24:A6:47:9E:8F', # Juniper
  'E8:24:A6:47:9E:90', # Juniper
  'E8:24:A6:47:9E:91', # Juniper
  'E8:24:A6:47:9F:31', # Juniper
  'E8:24:A6:47:9F:33', # Juniper
  '00:10:DB:FF:10:00', # Juniper
  '00:10:DB:FF:10:00', # Juniper
  '00:10:DB:FF:10:01', # Juniper
  '00:10:DB:FF:10:02', # Juniper
  '00:10:DB:FF:10:03', # Juniper
  '00:10:DB:FF:10:04', # Juniper
  '02:00:4C:4F:4F:50', # Microsoft Loopback Adapter
  '0A:00:27:00:00:0D', # VirtualBox
  '0A:00:27:00:00:11', # VirtualBox
  '20:41:53:59:4E:FF', # RAS Sync Adapter
  '44:45:53:54:42:00', # Nortel
  'AC:DE:48:00:11:22', # Apple iBridge Touchbar
  'D4:77:98:1E:D3:5F', # ESXI
  'D4:77:98:1E:D1:7F'  # ESXI
);

##
# Validates and normalizes a MAC address
#
# @param mac : required string MAC address to format
#
# @remark formats supported:
#         Cisco    : "0abb.0001.2289"
#         ifconfig : "0A:BB:00:01:22:89"
#         ipconfig : "0A-BB-00-01-22-89"
#         Solaris  : "A:BB:0:1:22:89"
#
# @return mac as  xx:xx:xx:xx:xx:xx (all upper case) or
#         FALSE if mac did not match a known pattern
##
function validate_and_normalize_mac(mac)
{
  if(isnull(mac))
    mac = _FCT_ANON_ARGS[0];

  # Various format regex
  local_var ifconrgx = "^"+IFCONFIG_MAC_RGX+"$";
  local_var ciscorgx = "^"+CISCO_MAC_RGX+"$";
  local_var solarrgx = "^"+SOLARIS_MAC_RGX+"$";
  mac = toupper(mac); # All formats are made upper case

  if(mac =~ ifconrgx)
  {
    mac = ereg_replace(string:mac, pattern:"-", replace:":");
    return mac;
  }
  else if(mac =~ ciscorgx)
  {
    mac = ereg_replace(string:mac, pattern:"\.", replace:":");
    mac = ereg_replace(string:mac, pattern:"([0-9A-F]{2})([0-9A-F]{2})(:|$)", replace:"\1:\2\3");
    return mac;
  }
  else if(mac =~ solarrgx)
  {
    # Solaris likes to show macs like 0:A:32:19:F:AA meaning
    # we have to pad out the missing 0s to normalize it to
    # 00:0A:32:19:0F:AA
    local_var digits = make_list();
    local_var digit  = "";
    mac = split(mac, sep:":", keep:FALSE);
    foreach digit (mac)
    {
      if(strlen(digit) < 2)
        digit = "0"+digit;
      digits = make_list(digits,digit);
    }
    return join(digits,sep:":");
  }
  else
  {
    dbg::detailed_log(lvl:1, msg:'Failed to normalize MAC address: ' + mac);
    return FALSE; # Does not appear to be a valid mac
  }
}

##
# Parses MACs discovered with SNMP
#
# @remark uses KB "SNMP/ifPhysAddress/" (set by snmp_ifaces.nasl)
#
# @return always a list of MACs (maybe empty)
##
function get_snmp_macs()
{
  local_var macs = make_list();
  local_var macidx = 0;
  local_var mac = get_kb_item("SNMP/ifPhysAddress/" + macidx);
  while (!isnull(mac))
  {
    macs[macidx] = mac;
    macidx += 1;
    mac = get_kb_item("SNMP/ifPhysAddress/" + macidx);
  }
  return macs;
}

##
# Parses MACs from various CLI-based OSes such as Cisco IOS, Cisco NX-OS, Juniper Junos
#
# @remark uses KB "Host/raw_macs" (set by ssh_get_info.nasl)
#
# @return always a list of MACs (maybe empty)
##
function get_host_raw_macs()
{
  local_var macs = make_array();
  local_var buf  = get_kb_item("Host/raw_macs");
  if(empty_or_null(buf))
    return make_list();
  return split(buf, sep:',', keep:FALSE);
}

##
# Parses macs from the output of ifconfig
#
# @remark uses KBs "Host/ifconfig" (set by ssh_get_info.nasl) and
#                  "Host/ifconfig/mac_addrs" (set by ifconfig_mac.nasl)
# 
# @return always a list of MACs (maybe empty)
##
function get_ifconfig_macs()
{
  local_var macs    = make_list();
  local_var line    = "";
  local_var matches = NULL;
  local_var iface   = NULL;

  # MAC addresses from ifconfig_mac.nasl
  # SSH run commands (ifconfig, netstat, nwmgr, lanscan)
  local_var kb_mac_addrs = get_kb_item("Host/ifconfig/mac_addrs");
  if (!empty_or_null(kb_mac_addrs))
  {
    matches = split(kb_mac_addrs, sep:'\n', keep:FALSE);
    if (!empty_or_null(matches))
    {
      macs = make_list(macs, matches);
    }
  }

  # MAC addresses from ssh_get_info.nasl from ifconfig
  # This is a bit redundant but below is the original code
  local_var buf = get_kb_item("Host/ifconfig");
  if(empty_or_null(buf))
    return macs;

  buf = split(buf, sep:'\n', keep:FALSE);
  foreach line (buf)
  {
    matches = NULL;
    line = tolower(line);

    # Pull out the interface label if we're on that line
    matches = pregmatch(string:line, pattern:"^([a-z0-9]+:)");
    if(!empty_or_null(matches))
      iface = matches[1];

    # Skip all lines belonging to "virtual" interfaces
    # we only want hardware MACs
    if(iface =~ "^(vmnet[0-9]+|veth[0-9a-z]{6}|virbr[0-9]+)")
    {
      dbg::detailed_log(lvl:1, msg:'Skipping virtual interface: ' + iface);
      continue;
    }

    # Regular ifconfig macs
    matches = pregmatch(string:line, pattern:"(hwaddr|ether) ("+IFCONFIG_MAC_RGX+")");
    # Now try solaris ifconfig macs
    if(empty_or_null(matches))
      matches = pregmatch(string:line, pattern:"(hwaddr|ether) ("+SOLARIS_MAC_RGX+")");
    # Add parsed mac
    if(!empty_or_null(matches))
      macs = make_list(macs, matches[2]);
  }
  return macs;
}

##
# Parses virtual macs from the output of ifconfig
#
# @remark uses KBs "Host/ifconfig" (set by ssh_get_info.nasl) and
#                  "Host/ifconfig/mac_addrs" (set by ifconfig_mac.nasl)
# 
# @return always a list of MACs (maybe empty)
##
function get_virtual_ifconfig_macs()
{
  local_var macs    = make_list();
  local_var line    = "";
  local_var matches = NULL;
  local_var iface   = NULL;
  local_var vmacs = NULL;
  local_var vkey = NULL;
  local_var virtual_mac;

  vmacs = get_kb_list("Host/iface/*/virtual");
  foreach vkey (keys(vmacs))
  {
    vkey = vkey - "virtual" + "mac";
    virtual_mac = get_kb_item(vkey);
    macs = make_list(macs, virtual_mac);
  }

  # MAC addresses from ssh_get_info.nasl from ifconfig
  # This is a bit redundant but below is the original code
  local_var buf = get_kb_item("Host/ifconfig");
  if(empty_or_null(buf))
    return macs;

  buf = split(buf, sep:'\n', keep:FALSE);
  foreach line (buf)
  {
    matches = NULL;
    line = tolower(line);

    # Pull out the interface label if we're on that line
    matches = pregmatch(string:line, pattern:"^([a-z0-9]+:)");
    if(!empty_or_null(matches))
      iface = matches[1];

    # Skip all lines NOT belonging to "virtual" interfaces
    # we only want virtual MACs here
    if(iface !~ "^(vmnet[0-9]+|veth[0-9a-z]{6}|virbr[0-9]+)")
    {
      dbg::detailed_log(lvl:1, msg:'Skipping physical interface: ' + iface);
      continue;
    }

    # Regular ifconfig macs
    matches = pregmatch(string:line, pattern:"(hwaddr|ether) ("+IFCONFIG_MAC_RGX+")");
    # Now try solaris ifconfig macs
    if(empty_or_null(matches))
      matches = pregmatch(string:line, pattern:"(hwaddr|ether) ("+SOLARIS_MAC_RGX+")");
    # Add parsed mac
    if(!empty_or_null(matches))
      macs = make_list(macs, matches[2]);
  }
  return macs;
}

##
# Parses MACs from WMI queries
#
# @remark KB "Host/WMI/mac_addrs" (set by wmi_list_interfaces.nbin)
#
# @return always a list of MACs (maybe empty)
##
function get_wmi_macs()
{
  local_var macs = make_list();
  local_var wmi_macs = get_kb_item('Host/WMI/mac_addrs');

  if (!empty_or_null(wmi_macs))
  {
    macs = split(wmi_macs, sep:'\n', keep:FALSE);
  }

  return macs;
}

##
# Parses virtual MACs from WMI queries
#
# @remark KB "Host/WMI/virtual_mac_addrs" (set by wmi_list_interfaces.nbin)
#
# @return always a list of MACs (maybe empty)
##
function get_virtual_wmi_macs()
{
  local_var macs = make_list();
  local_var wmi_macs = get_kb_item('Host/WMI/virtual_mac_addrs');

  if (!empty_or_null(wmi_macs))
  {
    macs = split(wmi_macs, sep:'\n', keep:FALSE);
  }

  return macs;
}

##
# Checks if the provided MAC address is blacklisted
#
# @param mac normalized mac address
#
# @return TRUE if mac is blacklisted, FALSE otherwise
##
function is_blacklisted(mac)
{
  # MAC address
  var blacklisted_mac;

  mac = validate_and_normalize_mac(mac:mac);

  foreach blacklisted_mac (BLACKLISTED_MACS)
    if (mac == blacklisted_mac)
      return TRUE;

  # Interface
  var iface_list = get_kb_list('Host/iface/id');
  var iface_macs, iface_mac;
  foreach var iface (iface_list)
  {
    if (iface !~ '^virbr[0-9]+')
      continue;

    iface_macs = get_kb_list(strcat('Host/iface/', iface, '/mac'));

    foreach iface_mac (iface_macs)
    {
      iface_mac = validate_and_normalize_mac(mac:iface_mac);

      if (mac == iface_mac)
        if (iface =~ '^virbr[0-9]+' && mac =~ '^52:54:00')
          return TRUE;
    }
  }

  return FALSE;
}

##
# Consolidate MAC addresses from various sources
#
# @return list of all MAC addresses gathered from various sources
#         NULL if an no MAC addresses were detected
##
function get_all_macs()
{
  # Check if MAC addresses were already gathered
  local_var unique_macs = get_kb_item("Host/mac_addrs");
  if (!empty_or_null(unique_macs)) return make_list(unique_macs);

  # Gather all available MAC addresses
  local_var current_mac = NULL;
  local_var raw_macs = make_list();
  var filter;

  # Multiple MAC addresses
  raw_macs = make_list(get_host_raw_macs(), raw_macs);
  raw_macs = make_list(get_ifconfig_macs(), raw_macs);
  raw_macs = make_list(get_snmp_macs(), raw_macs);
  raw_macs = make_list(get_wmi_macs(), raw_macs);

  # Single MAC address
  current_mac = get_kb_item("SMB/mac_addr"); # From netbios_name_get.nasl
  if (!empty_or_null(current_mac) && current_mac)
    raw_macs = make_list(current_mac, raw_macs);
  
  current_mac = get_kb_item("ARP/mac_addr"); # From ping_host.nasl / bad_vlan.nasl
  if (!empty_or_null(current_mac) && current_mac)
  {
    # Classify
    #  - limit this to ARP MAC addresses for now
    var classifier = new mac_address::classifier(current_mac);
    classifier.classify_arp();

    if (!filter)
      append_element(var:raw_macs, value:current_mac);
  }

  if (empty_or_null(raw_macs)) return NULL;

  # Normalize gathered MAC addresses and ensure uniqueness
  unique_macs = make_array();
  local_var normalized = "";
  local_var unique_macs_list = make_list();

  foreach current_mac (raw_macs)
  {
    normalized = validate_and_normalize_mac(current_mac);
    # make sure the normalized MAC is not FALSE, NULL, or a loopback address
    if (normalized && !empty_or_null(normalized) && !is_blacklisted(mac:normalized))
    {  
      if (empty_or_null(unique_macs[normalized]))
      {
        append_element(var:unique_macs_list, value:normalized);
      }
      unique_macs[normalized] = current_mac;
    }
  }

  if (empty_or_null(unique_macs)) return NULL;

  set_kb_item(name:"Host/mac_addrs", value:join(unique_macs_list, sep:'\n'));

  return unique_macs_list;
}

##
# Consolidate virtual MAC addresses from various sources
#
# @return list of all virtual MAC addresses gathered from various sources
#         NULL if an no virtual MAC addresses were detected
##
function get_virtual_macs()
{
  # Check if virtua MAC addresses were already gathered
  local_var unique_macs = get_kb_item("Host/virtual_mac_addrs");
  if (!empty_or_null(unique_macs)) return unique_macs;

  local_var raw_macs = make_list();
  local_var current_mac = NULL;

  # Multiple MAC addresses
  raw_macs = make_list(get_virtual_ifconfig_macs(), raw_macs);
  raw_macs = make_list(get_virtual_wmi_macs(), raw_macs);

  if (empty_or_null(raw_macs)) return NULL;

  # Normalize gathered MAC addresses and ensure uniqueness
  unique_macs = make_array();
  local_var normalized = "";

  foreach current_mac (raw_macs)
  {
    normalized = validate_and_normalize_mac(current_mac);
    # make sure the normalized MAC is not FALSE, NULL, or a loopback address
    if (normalized && !empty_or_null(normalized) && !is_blacklisted(mac:normalized))
      unique_macs[normalized] = current_mac;
  }

  if (empty_or_null(unique_macs)) return NULL;

  unique_macs = sort(keys(unique_macs));
  
  set_kb_item(name:"Host/virtual_mac_addrs", value:join(unique_macs, sep:'\n'));

  return unique_macs;
}


##
#  Binary Search shared functions
##

function my_cmp(a, b)
{
  a = substr(a, 0, 6);
  if (a == b) return 0;
  if (a < b) return -1;
  return 1;
}

function my_bsearch(v, e)
{
  local_var	n, i, i1, i2, c;

  n = max_index(v);
  i1 = 0; i2 = n;
  while (i1 < i2)
  {
    i = (i1 + i2) / 2;
    c = my_cmp(a: v[i], b: e);
    if (c == 0) return v[i];
    if (c < 0) i1 = i+1;
    else i2 = i;
  }
  return NULL;
}
