#TRUSTED 20d204e1d9b87a8060ac6be742066b3a58479af97b68ea0e6d08080bb3c9a71dc7413ea4633c19b495e82a58f701993985c2ab9cf76b4064bd95fc972dfd1bd6a5ebb1b14d49c28b83e9199f14f5abfbef3b2b4fca2c621d54882c988d1608de40d6817c899389fd20092c7d143ad3b68b784f1dffa6f71206cde02df44f31a5cd02957369ea5195a48ebbde7ffc1a5c4f3e3c320243e695f2395cb02e0e433e6a897599bfc5efa698f8b141ced1bf12e3d1b42dda8e865151da7f5ec26d6da6fb97461c7acdb517c61d27f7763f40fe6dcea6734d0bfe4b4eb30f6f23b5e37b0072cfa34346573781a1d9485ef80873011d6a98b85ca4444e2aedfd68c24fa6b42a1de797505d7b31ddf9d01228fd1294192d9d845524babb9f0aac0aa122aa01ffe4997c9d15b9420405b4ff9a657b029079497a29e1e238a785821cde4c6977715fdae3c864f81fb6c5d05dd569ee8dedc867b970d976f375b58620cd2bf06e38bb89ef5bb5106f327ea73078e037719b1302b6d0d04d672e62d1a408771f121f07b14bb2664a0ae62b86153c56de7f802b935a3844340c1c84b81dc8ecd892342fa1374ed9e9b2a2d926f7f7a5a3d56a9cfb07909940177d5bb2ca6c6d292b9e37f4d8dc31a587df93329ac04fd73ca20325a0a1d9b7c718a552d1e439a1abc3a6b597d909985131a6655fbc0d679f51b26a774e9bcc4b41a3ab0fefb04e
#TRUST-RSA-SHA256 9b33939feb7046f2a68ef4c93d396f30974cedd9f47c322a1a416a76e809179efe3d361bfbbb502d4bd6290d513694b9b348b01a39cca93d3ba53b084526f8e9072198ce20d9531b200210267bc67c0debf6397a685c6f40cda8685a0d7ecad53c91bdb01b5f01fb626fc0673f4b6b67e2ed448f0912d5cc376117c16b3bb3f15959ca39c78d0bdc00ad1cfa77e697e1f783a07c935d3a926bf7e10a6bb045273ae84e8ceaa754dfcccc43c195682091a89dcc8cf5f793495cf682e67e87f35b3f5143b393550fe1047255777ddb8b7be138ad97aa2cd4b37a399988e7983126e2e395fb19f02702a10d9a75e0d825df79a2e46dffbb8abb897f8351da8009fea2147ea646908e655e273c7e6cc463e594838225f74f076aedfdb408a6108353902ef33ccda35cd843a6e752bd58c6c5da8a4c4655cb4b4fc2492faca8b147bbc1d8421315686d842a99e89c2f4969ff0f6f222f4a2ab9181197d8cd2fcd7780b925d3ca563590374e2b2a7642da8aa5352b7c95e3ca95a4338a372aafa39050edbec6883adb62806b1fa43150c367785c0761d05c8c2081f70cd10ac38b887f3ea80903adac6852aceffa702c98a591f681af26d88731601ae8851cf4cec25bbe1c2415835b0cf8e04bb7e4f075b108e8b08768e7dacd55178b2232288818afb65340befa15cc9d1f26f0635a4079e7d5f3723b4b9884898094475f914d6a9f

###
#
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable, Inc.
#
# @NOGPL@
#
# host_summary.inc
#
# Revision: 1.11
###

include('agent.inc');
include('compat_shared.inc');
include('debug.inc');
include('install_func.inc');
include('ip.inc');
include('ip6.inc');
include('mac_address_func.inc');
include('rpm.inc');
include('spad_log_func.inc');
include('ports.inc');
include('json2.inc');
include('resolv_func.inc');

##
# Builds an array of FQDNS addressed by IPs they resolve to using 'Host/FQDNS_list' KB entry set by asset_attribute_fqdn.nasl plugin
#
# @return an array of {IP:[FQDNs]}, or NULL if 'Host/FQDNS_list' KB entry is missing
##
function build_fqdns_array()
{
  var fqdns_list = get_kb_item('Host/FQDNS_list');
  if(empty_or_null(fqdns_list))
  {
    dbg::detailed_log(src:FUNCTION_NAME, lvl:1, msg:"'Host/FQDNS_list' KB entry is missing!");
    return NULL;
  }
  
  fqdns_list = json_read(fqdns_list);  
  fqdns_list = fqdns_list[0]; #json_read will return a 1-long list with the actual list inside
  fqdns_list = fqdns_list['FQDNS'];

  var fqdns_array = {};
  var fqdn, ipv4_list, ipv6_list;
  foreach(var fqdns_entry in fqdns_list)
  {
    fqdn = fqdns_entry['FQDN'];
    
    # validate fqdn
    if (empty_or_null(fqdn) ||
      fqdn == get_host_ip() ||
      fqdn !~ "^[A-Za-z0-9]+((\.|-)[A-Za-z0-9]+)*\.[A-Za-z]{2,}$"
    ) continue;

    ipv4_list = fqdn_resolv(name:fqdn, fqdn:TRUE);
    foreach(var ipv4 in ipv4_list)
    {
      if(empty_or_null(ipv4)) continue;

      if(isnull(fqdns_array[ipv4])) fqdns_array[ipv4] = [fqdn];
      else append_element(var:fqdns_array[ipv4], value:fqdn);
    }

    ipv6_list = fqdn_resolv(name:fqdn, ipv6:TRUE, fqdn:TRUE);    
    foreach(var ipv6 in ipv6_list)
    {
      if(empty_or_null(ipv6)) continue;

      if(isnull(fqdns_array[ipv6])) fqdns_array[ipv6] = [fqdn];
      else append_element(var:fqdns_array[ipv6], value:fqdn);
    }
  }
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'FQDNs array built', msg_details:{'fqdns_array':{'lvl':2, 'value':fqdns_array}});
  return fqdns_array;
}

##
# Adds FQDNs to a list of FQDNs associated with a given interface IP
# @param fqdns_array An array built by build_fqdns_array()
# @param current_list A list of FQDNs to poossibly expand
# @param ip An IP address to retrieve FQDNs for
# @return An expanded list of FQDNs
##
function add_fqdns_to_list(&fqdns_array, &current_list, ip)
{ 
  if(empty_or_null(fqdns_array))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'fqdns_arrray is empty or null, aborting');
    return current_list;
  }
  if(empty_or_null(fqdns_array[ip]))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'no fqdns found for ip, aborting', msg_details:{'IP':{'lvl':1, 'value':ip}});
    return current_list;
  }
  var new_list = make_list(current_list, fqdns_array[ip]);
  dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:'FQDNS added for IP', msg_details:{'New FQDNs list':{'lvl':3, 'value':new_list}, 'IP':{'lvl':2, 'value':ip}});
  return new_list;
}

##
# Checks if IPv4 falls into one of private ranges, i.e. 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16
# @param ip String representation of an IP address
# @return 'yes' for private IPs, 'no' for public IPs, 'unknown' for empty/NULL ips
## 
function is_private_ipv4(ip)
{
  if(empty_or_null(ip)) return 'unknown';
  if(ip =~ "^10\.") return 'yes';
  if(ip =~ "^192\.168\.") return 'yes';
  var ip_parts = split(ip, sep:'.', keep:FALSE);
  var ip_part_1 = int(ip_parts[0]);
  var ip_part_2 = int(ip_parts[1]);
  if(ip_part_1 == 172 && ip_part_2 >=16 && ip_part_2 <= 31) return 'yes';
  return 'no';
}

##
# Checks if IPv6 falls into the unique local address range i.e. fc00::/7, which means fc00::/8 and fd00::/8
# @param ip String representation of an IP address
# @return 'yes' for unique local IPs, 'no' for other IPs, 'unknown' for empty/NULL ips
## 
function is_private_ipv6(ip)
{
  if(empty_or_null(ip)) return 'unknown';
  var prefix = ip[0] + ip[1];
  if (prefix == 'fc' || prefix == 'fd') return 'yes';
  return 'no';
}

##
# Builds an array enumerating the network interfaces information collected during the scan.
#
# @return An array enumerating the interfaces information, the string "Not Collected" if no information was collected.
#
# @remark This function sets the "interfaces" internal tag via ``report_tag_internal()``.
##
function enumerate_interfaces()
{
  local_var iface_list, interfaces, iface;
  local_var mac, ipv4_list, ipv6_list, ip_list, vendor_name;
  local_var aliased, virtual, is_target, kb_prefix, hostname_f;
  local_var fqdn, i, ipv4, ipv6;
  var assignment, ip_value, fqdns_array, if_fqdns;
  # Collected in ip_assignment_method.nasl
  var assignment_map = json_read(get_kb_item('Host/iface/assignment_map'));
  if(empty_or_null(assignment_map)) assignment_map = {'IPv4':[], 'IPv6':[]};
  else assignment_map = assignment_map[0]; #json_read will return a 1-long list with the actual map inside

  iface_list = get_kb_list("Host/iface/id");

  if (empty_or_null(iface_list))
    return "Not Collected";

  fqdns_array = build_fqdns_array();

  interfaces = make_nested_array();

  foreach iface (iface_list)
  {
    if (!empty_or_null(iface))
    {
      mac = NULL;
      ipv4_list = NULL;
      ipv6_list = NULL;
      ip_list = NULL;
      aliased = NULL;
      virtual = NULL;
      if_fqdns = [];

      is_target = FALSE;
      fqdn = NULL;

      kb_prefix = "Host/iface/"+iface;
      mac = get_kb_item(kb_prefix+"/mac");
      ipv4_list = get_kb_list(kb_prefix+"/ipv4");
      ipv6_list = get_kb_list(kb_prefix+"/ipv6");
      aliased = get_kb_item(kb_prefix+"/aliased");
      virtual = get_kb_item(kb_prefix+"/virtual");

      interfaces[iface] = make_nested_array();

      # mac address
      if (!empty_or_null(mac))
      {
        vendor_name = get_kb_item("Host/ethernet_manufacturer/macs/"+ toupper(mac));
        # Suppress certain MAC addresses from reporting to avoid erroneously merging different assets
        if (is_blacklisted(mac:mac))
          interfaces[iface]['suppressed mac address'] = mac;
        else
          interfaces[iface]['mac address'] = mac;
        if (!empty_or_null(vendor_name))
          interfaces[iface]['vendor'] = vendor_name;
      }

      # ip addresses
      ip_list = make_nested_list();
      i = 0;
      if (!empty_or_null(ipv4_list))
      {
        foreach ipv4 (ipv4_list)
        {
          if (ipv4 == get_host_ip()) is_target = TRUE;

          if (ipv4::validate(ip:ipv4, assignable:true))
            ip_value = make_array('type', 'ipv4','value', ipv4);
          else
            ip_value = make_array('type', 'ipv4 (suppressed)', 'value', ipv4);

          assignment = assignment_map['IPv4'][ipv4];  
          if(!empty_or_null(assignment)) ip_value['assignment_method'] = assignment;
          ip_value['rfc1918-private'] = is_private_ipv4(ip:ipv4);

          ip_list[i++] = ip_value;
          if_fqdns = add_fqdns_to_list(fqdns_array:fqdns_array, current_list:if_fqdns, ip:ipv4);
        }
      }
      if (!empty_or_null(ipv6_list))
      {
        foreach ipv6 (ipv6_list)
        {
          assignment = assignment_map['IPv6'][ipv6];
          if(empty_or_null(assignment)) assignment = 'unknown';

          if (ipv6::validate(ip:ipv6, assignable:true))
            ip_value = make_array('type', 'ipv6','value', ipv6);
          else
            ip_value = make_array('type', 'ipv6 (suppressed)', 'value', ipv6);

          assignment = assignment_map['IPv6'][ipv6];  
          if(!empty_or_null(assignment)) ip_value['assignment_method'] = assignment;

          ip_value['rfc4193-private'] = is_private_ipv6(ip:ipv6);

          ip_list[i++] = ip_value;
          if_fqdns = add_fqdns_to_list(fqdns_array:fqdns_array, current_list:if_fqdns, ip:ipv6);
        }
      }
      if (len(ip_list) > 0)
        interfaces[iface]['ip addresses'] = ip_list;      

      # aliased
      if (!empty_or_null(aliased))
        interfaces[iface]['aliased'] = aliased;

      # virtual
      if (!empty_or_null(virtual))
        interfaces[iface]['virtual'] = virtual;

      # fqdns
      if(!empty_or_null(if_fqdns))
        interfaces[iface]['fqdns'] = list_uniq(if_fqdns);

      if (is_target)
      {
        # set FQDN for scan target's interface only
        if (agent())
        {
          fqdn = get_kb_item("Host/agent/FQDN");
          if (isnull(fqdn)) fqdn = agent_fqdn();
        }
        else
        {
          fqdn = get_kb_item("Host/FQDN");
          if (isnull(fqdn)) fqdn = get_host_fqdn();
        }

        # validate fqdn
        if (empty_or_null(fqdn) ||
          fqdn == get_host_ip() ||
          fqdn !~ "^[A-Za-z0-9]+((\.|-)[A-Za-z0-9]+)*\.[A-Za-z]{2,}$"
        )
          fqdn = NULL;

        if (!isnull(fqdn))
          interfaces[iface]['fqdn'] = fqdn;
      }
    }
  }

  if (!empty_or_null(interfaces))
  {
    interfaces = make_nested_array("interfaces", interfaces);
    dbg::detailed_log(lvl:2, msg:'interfaces:\n' + obj_rep(interfaces));
    report_tag_internal(tag:"interfaces", value:interfaces);
  }

  return interfaces;
}

##
# Builds an array enumerating the installed software information collected during the scan.
#
# @return [array] An array enumerating the installed software information.
#
# @remark This function goes through all of the ``installed_sw/*`` KB keys, OS packages managed by unix package managers
# and software enumerated via the Windows registry.
#
# @remark This function sets the "software" internal tag via ``report_tag_internal()``.
##
function enumerate_software()
{
  local_var os;
  local_var installed_kbs, key;
  local_var sw_inventory, app;
  local_var installs, install, app_paths;
  local_var display_names, version, install_date, install_location, res;
  local_var distro, distros, pkg_mgr, packages, package;
  local_var oracle_homes, ohome, components, component;

  distros = make_list(
    "Host/AIX/lslpp",
    "Host/AmazonLinux/rpm-list",
    "Host/CentOS/rpm-list",
    "Host/Debian/dpkg-l",
    "Host/FreeBSD/pkg_info",
    "Host/Gentoo/qpkg-list",
    "Host/HP-UX/swlist",
    "Host/MacOSX/packages",
    "Host/Mandrake/rpm-list",
    "Host/McAfeeLinux/rpm-list",
    "Host/OracleVM/rpm-list",
    "Host/RedHat/rpm-list",
    "Host/Slackware/packages",
    "Host/Solaris/showrev",
    "Host/Solaris11/pkg-list",
    "Host/SuSE/rpm-list",
    "Host/VMware/esxupdate",
    "Host/VMware/esxcli_software_vibs",
    "Host/XenServer/rpm-list",
    "Host/Junos_Space/rpm-list",
    "Host/AzureLinux/rpm-list",
    "Host/Alibaba/rpm-list"
  );

  sw_inventory = make_nested_array();
  app_paths = make_array();  # Used to track already detected paths and minimize duplication

  # We need to know the OS to do a thorough inventory of software
  os = get_kb_item("Host/OS");

  # Gather a list of software found via direct detection
  installed_kbs = get_kb_list("installed_sw/*");
  if (!empty_or_null(installed_kbs))
  {
    sw_inventory = make_nested_array();
    foreach app (sort(keys(installed_kbs)))
    {
      # This avoids reporting on webapps
      if (app =~ "^installed_sw\/[0-9]+\/$")
        continue;
      if (app =~ "^installed_sw\/[^\/]+$")
      {
        # Initialize the package object
        sw_inventory[app] = make_nested_array();

        app = app - 'installed_sw/';
        installs = get_installs(app_name:app);
        foreach install (installs[1])
        {
          app_paths[install["path"]] = TRUE;
          sw_inventory[app]["path"] = install["path"];
          sw_inventory[app]["version"] = install["version"];
          if (!empty_or_null(install["display_version"]))
            sw_inventory[app]["display_version"] = install["display_version"];
          if (!empty_or_null(install["extra"]))
            sw_inventory[app]["extra"] = install["extra"];
          if (!empty_or_null(install["extra_no_report"]) && !empty_or_null(install["extra_no_report"]["method"]))
            sw_inventory[app]["method"] = install["extra_no_report"]["method"];
          else
            sw_inventory[app]["method"] = "direct";

          if (!empty_or_null(install['cpe']))
            sw_inventory[app]['cpe'] = install['cpe'];
        }
      }
    }
  }

  # Windows software enumeration
  if ("windows" >< tolower(os))
  {
    # Gather a list of software found via registry enumeration
    display_names = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
    if (!empty_or_null(display_names))
    {
      foreach key (sort(keys(display_names)))
      {
        app = display_names[key];
        if ("hotfix" >< tolower(app) || tolower(app) =~ "update.*kb")
          continue;
        key = key - "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/";
        key = key - "/DisplayName";

        # Make sure this isn't a duplicate we have already seen
        if (empty_or_null(sw_inventory[app]))
        {
          version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/DisplayVersion");
          install_date = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/InstallDate");
          install_location = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+key+"/InstallLocation");

          sw_inventory[app] = make_nested_array();
          if (!empty_or_null(version))
            sw_inventory[app]["version"] = version;
          if (!empty_or_null(install_location))
            sw_inventory[app]["path"] = install_location;
          if (!empty_or_null(install_date))
            sw_inventory[app]["install_date"] = install_date;
          sw_inventory[app]["detection_method"] = "registry";
        }
      }
    }
  }
  else
  {
    if ('solaris 10' >< tolower(os))
    {
      packages = get_kb_list("Solaris/Packages/Versions/*");
      if (!empty_or_null(packages))
      {
        foreach package (keys(packages))
        {
          package = package - "Solaris/Packages/Versions/";
          sw_inventory[package] = make_array();
          sw_inventory[package]["version"] = packages[package];
          sw_inventory[package]["method"] = "pkginfo -x";
        }
      }
    }
    else if ('slackware' >< tolower(os))
    {
      packages = get_kb_item("Host/Slackware/packages");
      foreach package (split(packages, sep:'\n', keep:FALSE))
      {
        res = pregmatch(string:package, pattern: "^(.+)-([^-]+)-([^-]+)-([^-]+)$");
        if (!empty_or_null(res))
        {
          sw_inventory[res[1]] = make_array();
          sw_inventory[res[1]]["version"] = res[2];
          sw_inventory[res[1]]["method"] = "package log";
        }
      }
    }
    foreach pkg_mgr (distros)
    {
      packages = get_kb_item(pkg_mgr);
      if (!empty_or_null(packages))
      {
        pkg_mgr = ereg_replace(pattern:'^.*/.*/(.*)', replace:"\1", string:pkg_mgr);
        switch (pkg_mgr)
        {
          case "rpm-list":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = parse_rpm_name(rpm:package);
              if (!empty_or_null(res["name"]))
              {
                sw_inventory[res["name"]] = make_array();
                if (!empty_or_null(res["version"]))
                  sw_inventory[res["name"]]["version"] = res["version"];
                if (!empty_or_null(res["release"]))
                  sw_inventory[res["name"]]["version"] += res["release"];
                sw_inventory[res["name"]]["method"] = "rpm -qa";
              }
            }
            break;
          case "dpkg-l":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = pregmatch(string:package, pattern:'^([uirph][nicufhWt])\\s+([^\\s]+)\\s+([^\\s]+)\\s+(.*)');
              if (!empty_or_null(res))
              {
                sw_inventory[res[2]] = make_array();
                sw_inventory[res[2]]["version"] = res[3];
                sw_inventory[res[2]]["description"] = res[4];
                sw_inventory[res[2]]["extra"] = make_array("status", res[1]);
                sw_inventory[res[2]]["method"] = "dpkg -l";
              }
            }
            break;
          case "lslpp":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = split(package, sep:':', keep:FALSE);
              if (max_index(res) > 0)
              {
                sw_inventory[res[1]] = make_array();
                sw_inventory[res[1]]["version"] = res[2];
                if (res[7] =~ '^[^\\s+]')
                  sw_inventory[res[1]]["description"] = res[7];
                sw_inventory[res[1]]["method"] = "lslpp";
              }
            }
            break;
          case "pkg_info":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              local_var pkg_desc = '';
              res = pregmatch(string:package, pattern:'^([^\\s]+)\\s+(.*)$');
              if (!empty_or_null(res))
              {
                pkg_desc = res[2];
                res = split(res[1], sep:"-", keep:FALSE);

                if (!empty_or_null(res))
                {
                  local_var pkg_name = res[0];
                  local_var index;
                  for (index = 1; index < max_index(res) - 1; index++)
                  {
                    pkg_name += "-" + res[index];
                  }

                 sw_inventory[pkg_name] = make_array();
                 sw_inventory[pkg_name]["version"] = res[index];
                 if (!empty_or_null(pkg_desc))
                   sw_inventory[pkg_name]["description"] = pkg_desc;
                 sw_inventory[pkg_name]["method"] = "pkg_info";
                }
              }
            }
            break;
          case "qpkg-list":
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = pregmatch(string:package, icase:1, pattern:'(^[a-z0-9-]+)/([A-Za-z0-9\\+\\-]+)-(.*)');
              if (!empty_or_null(res))
              {
                pkg_name = res[1] + "/" + res[2];
                sw_inventory[pkg_name] = make_array();
                sw_inventory[pkg_name]["version"] = res[3];
                sw_inventory[pkg_name]["method"] = "qpkg-list";
              }
            }
            break;
          case "swlist":
            packages = split(packages, sep:'\n', keep:FALSE);
            for (index = 5; index < len(packages); index++)
            {
              # Only grab the product, not the fileset info
              if (packages[index] =~ '^#')
              {
                res = pregmatch(string:packages[index], pattern:'^#\\s([^\\s]+)\\s+([^\\s]+).*$');
                if (!empty_or_null(res))
                {
                  sw_inventory[res[1]] = make_array();
                  sw_inventory[res[1]]["version"] = res[2];
                  sw_inventory[res[1]]["method"] = "swlist";
                }
              }
            }
            break;
          case "pkg-list":
           packages = split(packages, sep:'\n', keep:FALSE);
           for (index = 1; index < max_index(packages); index++)
           {
             res = pregmatch(string:packages[index], pattern:'^([^\\s]+)\\s+([^\\s]+).*$');
             if (!empty_or_null(res))
             {
               sw_inventory[res[1]] = make_array();
               sw_inventory[res[1]]["version"] = res[2];
               sw_inventory[res[1]]["method"] = "Solaris11 pkg-list";
             }
           }
           break;
          default:
            continue;
        }
      }
    }
  }
  if (!empty_or_null(sw_inventory))
  {
    sw_inventory = make_nested_array("installed_software", sw_inventory);
    dbg::detailed_log(
      lvl: 3,
      src: FUNCTION_NAME,
      msg: "Gathered the inventory software",
      msg_details: {
        "Inventory": {"lvl": 3, "value": obj_rep(sw_inventory)}});
    report_tag_internal(tag:"software", value:sw_inventory);
  }
}

##
# Builds an array enumerating the LDAP, WMI and SMB users information collected during the scan.
#
# @return [array] An array enumerating the users information.
#
# @remark This function sets the "users" internal tag via ``report_tag_internal()``.
##
function enumerate_users()
{
  local_var username, kb_prefix, val, type, i, att, proto;
  local_var users = make_nested_array();

  local_var enum_types = make_list("LDAP", "WMI", "SMB");

  local_var user_types = make_array(
    # display, kb
    "Domain", "",
    "Local", "Local"
  );

  local_var attrs = make_nested_array(
    "LDAP", make_list(),
    "WMI", make_list(
      "SID",
      "Disabled",
      "Lockout",
      "PasswordChangeable"
    ),
    "SMB", make_list(
      "LogonTime",
      "LogoffTime",
      "PassLastSet",
      "KickoffTime",
      "PassCanChange",
      "PassMustChange",
      "ACB"
    )
  );

  foreach proto (enum_types)
  {
    # Special handling for Multi-port LDAP to account for KB keys LDAP/<port>/Users/...
    var count, loop_prefix;
    if (proto == "LDAP")
    {
      var port, ports;
      ports = get_service_port_list(svc:"ldap", exit_on_fail:FALSE);

      foreach port (ports)
      {
        # look at Domain and Local
        foreach type (keys(user_types))
        {
          if (empty_or_null(users[type])) users[type] = make_nested_array();
	
          # e.g. LDAP/<port>/<type> : LDAP/389/LocalUsers/ , LDAP/3268/Users , etc
          kb_prefix = strcat(proto,"/",port,"/",user_types[type],"Users/");

          count = get_kb_item(kb_prefix+"count");
          if (isnull(count))
          {
	    continue;
	    # LDAP, not SMB, so skip this check
            #if (proto != "SMB") continue;
            ## see if SMB null session was enumerated
            #count = get_kb_item(kb_prefix+"NullSession/count");
            #if (isnull(count)) continue;
            #kb_prefix += "NullSession/";
          }

          loop_prefix = NULL;
          # kb user index starts at 1
          for (i = 1; i <= count; i++)
          {
            loop_prefix = kb_prefix+i;
            username = get_kb_item(loop_prefix);
            if (isnull(username))
	    {
	      continue;
	    }

            # user attributes are not available for LDAP
            if (empty_or_null(users[type][port][username])) users[type][port][username] = make_nested_array();
          }
        }
      }
    }
    else
    {
      # look at Domain and Local
      foreach type (keys(user_types))
      {
        if (empty_or_null(users[type])) users[type] = make_nested_array();
        # e.g. SMB/LocalUsers/ or SMB/Users
        kb_prefix = proto+"/"+user_types[type]+"Users/";

        count = get_kb_item(kb_prefix+"count");
        if (isnull(count))
        {
          if (proto != "SMB") continue;
          # see if SMB null session was enumerated
          count = get_kb_item(kb_prefix+"NullSession/count");
          if (isnull(count)) continue;
          kb_prefix += "NullSession/";
        }

        loop_prefix = NULL;
        # kb user index starts at 1
        for (i = 1; i <= count; i++)
        {
          loop_prefix = kb_prefix+i;
          username = get_kb_item(loop_prefix);
          if (isnull(username)) continue;

          # set user attributes
          if (empty_or_null(users[type][username])) users[type][username] = make_nested_array();
          loop_prefix += "/Info/";

          foreach att (attrs[proto])
          {
            val = get_kb_item(loop_prefix+att);
            if (!isnull(val))
              users[type][username][att] = val;
          }
        }
      }
    }
  }

  # clean up empty lists/arrays
  foreach type (keys(users))
  {
    if (empty_or_null(users[type])) delete_element(idx:type, var:users);
  }

  if (!empty_or_null(users))
  {
    users = make_nested_array("Users", users);
    report_tag_internal(tag:"users", value:users);
  }
}

##
# Builds an array enumerating the LDAP and WMI groups information collected during the scan.
#
# @return [array] An array enumerating the groups information.
#
# @remark This function sets the "groups" internal tag via ``report_tag_internal()``.
##
function enumerate_groups()
{
  local_var protos, proto;
  local_var groups = make_nested_array();
  local_var group_count, user_count, group_attrs, user_attr, att;
  local_var group_name, username, loop_prefix, user_loop_prefix;
  local_var kb_prefix, i, k, type, members, admin;
  local_var types = make_array(
    'Domain', '',
    'Local', 'Local'
  );

  protos = make_nested_array(
   'LDAP', make_list(),
   'WMI', make_list('Hostname', 'SID')
  );

  foreach type (keys(types))
  {
    if (empty_or_null(groups[type])) groups[type] = make_nested_array();

    foreach proto (keys(protos))
    {
      kb_prefix = proto+'/'+types[type]+'Groups/';
      group_count = get_kb_item(kb_prefix+'count');

      if (isnull(group_count)) continue;

      for (i = 1; i <= group_count; i++)
      {
        loop_prefix = kb_prefix+i;
        group_name = get_kb_item(loop_prefix);
        if (isnull(group_name)) continue;
        groups[type][group_name] = make_nested_array();
        loop_prefix += '/Info/';

        group_attrs = protos[proto]; # a list
        foreach att (group_attrs)
        {
          groups[type][group_name][att] = get_kb_item(loop_prefix+att);
        }

        # enumerate group users
        user_count = get_kb_item(loop_prefix+'Members/count');
        if (isnull(user_count)) continue;
        members = make_list();
        for (k = 1; k <= user_count; k++)
        {
          user_loop_prefix = loop_prefix+'Members/'+k;
          username = get_kb_item(user_loop_prefix);
          if (isnull(username)) continue;
          members = make_list(username, members);
        }
        if (len(members) > 0)
          groups[type][group_name]['Members'] = members;
      }
    }
  }
  # Admins
  protos = make_nested_array(
    'LDAP', make_list('Domain', 'Domain Admins'),
    'SSH', make_list('Local', 'Admins')
  );

  local_var admins, context;
  foreach proto (keys(protos))
  {
    context = protos[proto][0]; # domain/local
    admins = get_kb_list(proto+"/"+context+"Admins/Members/*");

    if(!isnull(admins))
    {
      group_name = protos[proto][1];
      if (empty_or_null(groups[context]))
        groups[context] = make_nested_array();
      local_var admin_list = make_array();
      foreach admin (keys(admins))
      {
        admin_list[admins[admin]] = 1;
      }
      groups[context][group_name] = keys(admin_list);
    }
  }

  # clean up empty lists/arrays
  foreach type (keys(groups))
  {
    if (empty_or_null(groups[type])) delete_element(idx:type, var:groups);
  }

  if (!empty_or_null(groups))
  {
    groups = make_nested_array("Groups", groups);
    report_tag_internal(tag:"groups", value:groups);
  }
}

##
# Builds an array enumerating various login-related information collected during the scan.
#
# @return [array] An array enumerating the login-related information.
#
# @remark This function sets the "misc" internal tag via ``report_tag_internal()``.
#
# @remark For a definitive list of gathered information see the function's code.
# A tentative estimate of the gathered information is everything in
# the ``SSH/LocalUsers/*`` and ``SMB/LocalUsers/*`` KB items.
##
function enumerate_misc()
{
  local_var att, attrs, type, key;
  local_var misc = make_nested_array();

  local_var last_user_login = get_kb_item("SMB/last_user_login");
  if (!isnull(last_user_login))
    misc['Last User Login'] = last_user_login;

  local_var enum_types = make_nested_array(
    "SSH", make_array(
      "PwNeverExpires", "PwNeverExpires"
    ),
    "SMB", make_array(
      "AutoDisabled",  "Auto-disabled",
      "PwCantChange",  "PwCantChange",
      "Disabled",      "Disabled",
      "NeverChangedPw","NeverChangedPw",
      "NeverLoggedOn", "NeverLoggedOn",
      "PwNeverExpires","PwNeverExpires"
    )
  );

  foreach type (keys(enum_types))
  {
    attrs = enum_types[type];
    foreach att (keys(attrs))
    {
      local_var kb_list = get_kb_list(type+"/LocalUsers/"+att+"/*");
      local_var disp = attrs[att];
      if (!isnull(kb_list))
      {
        misc[disp] = make_list();
        foreach key (keys(kb_list))
        {
          misc[disp] = make_list(misc[disp], kb_list[key]);
        }
      }
    }
  }

  if (!empty_or_null(misc))
  {
    misc = make_nested_array("Misc", misc);
    report_tag_internal(tag:"misc", value:misc);
  }
}

##
# Set report_tag_internal 'cpe' tag with CPEs registered with ``register_install()``.
#
# @return true if CPEs found and reported successfully; false if no CPEs found; NULL if an error occurred.
#
# @remark This function reports via ``report_tag_internal()``.
##
function enumerate_cpes()
{
  var cpes;
  cpes = get_kb_list('installed_sw/*/cpe');

  if (empty_or_null(cpes))
    return false;

  # Return list with only CPEs
  cpes = list_uniq(make_list(cpes));

  if (empty_or_null(cpes))
    return NULL;

  cpes = { 'cpes' : cpes };
  dbg::detailed_log(
    lvl: 3,
    src: FUNCTION_NAME,
    msg: "Enumerated CPEs",
    msg_details: {
      "CPEs": {"lvl": 3, "value": obj_rep(cpes)}});
  report_tag_internal(tag:'cpes', value:cpes);

  return true;
}

##
# Set host tags for ports identified outside of the scan port range.
#
# @return [boolean] true if successful; false otherwise.
#
# @remark This function reports via ``report_xml_tag()``.
##
function enumerate_out_of_range_ports()
{
  var out_of_range_ports, protos, proto, port, tag;

  # These scan configurations make the check irrelevant
  #  Agents
  if (agent())
    return false;

  #  Local port enumerators (port range is treated as 'all' port)
  if (!empty_or_null(ports::scan::get_local_port_enumerator()))
    return false;

  #  Full port range and both TCP and UDP scanned
  if (get_one_kb_item('Host/TCP/full_scan') && get_one_kb_item('Host/UDP/full_scan'))
    return false;

  out_of_range_ports = ports::scan::get_out_of_range();

  # Explicitly check 'tcp' and 'udp' to prevent unforeseen issues
  protos = [ 'tcp', 'udp' ];
  foreach proto (protos)
  {
    # Skip full port scan range
    if (get_one_kb_item(strcat('Host/', toupper(proto), '/full_scan')))
    {
      dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:'Skipping protocol due to full port range scanned: ' + proto);
      continue;
    }

    foreach port (out_of_range_ports[proto])
    {
      if (ports::validate(port:port))
      {
        tag = strcat('enumerated-ports-', port, '-', proto);

        dbg::detailed_log(lvl:4, src:FUNCTION_NAME, msg:'Registering tag: ' + tag);
        report_xml_tag(tag:tag, value:'open');
      }
    }
  }

  return true;
}
