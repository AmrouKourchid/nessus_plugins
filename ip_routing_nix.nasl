#TRUSTED 024a73997408eccc7e2e5c0c43980be16204fb05cd8fbe8bd10f3cee06ab0b63fd9e3ff6fe7630d4c7d952a745867fbff2c288ecb5b41287fc30a5d1280c821304ff8de5f8ad829c6e6739d4f388ceaf0a812fb5897db906336662dcec214c998e252d39561c62e9de98130b82528fb2ca141acc443c8e61676ca664d24822da7d9c8be5f33fb02a7842a4a7e4aede1820936335a6ad8b18b46a3fa9fd8e0e6cad5ad6edaf7d39ba5bfcc8d0ef756bf12afde5cbeeb2f226cbc90603636bc91ee39ad9c3b65600cf8ff4c91e40907d7ee8a75a7441d4b59d0383f9a2303509791bbfe09e62d2d33c3c9662cefbd445a2f01feeef14d9a3c2b55d370afa089bd031c99128b753c5d5b71098920bcb45f04733492c0a21a07aff324eeb1b7826ce08fbc3baf506fd02c88abd913d6c7b7dd144c8be620705aac80abbadc9ae14168941fb87e1da6fd53f3a3b3b581c6046a76b2a56acd99f8479faa999d88fcad2434bc8de484b645145140eda77a58fb8e25e52063d039cb81d678b844d4a8a8c221d31150151ed7395a075acc75f7100502730960d6bc7cf973a5682f6fac3e3a3e6850b5b2d209746ca955a7832df6f78a177dd709727864979f928317b70207bf62e7b8cd613e50e1dd82426ac822fa216e9ce480ce99547e8c76fa7122e686f95344e10120cf48050b3574fda0862a5667c4bc3b53cee3c6797dba0687e4f
#TRUST-RSA-SHA256 0053f76c8897e0b0cc163b5543c7b2414d3e6198e960c7a091b3412f2e38cda7de4fd28b1a0d0bf1ce7f8927ac8a8fcf497289e1d6623ef837500542f1f48cf92d1758d3762c13a817cfa935d032034513dac7ad2b7ebe3c891a370b0f33eaf099a2a49e9b75657f68a4d8fdb12f30f844d32465d91ba90acf71ab2858a9c5d91ff800f050b1dec07caf1bf80e74214c6b9fe409ea22e4d344dc05b9746d61857f09d8eb11bbf1263c66e440b6fa68ec053a86c5e743b435a9c0534c01f062968efb7ad3c21fe653cd360e1854d5f372475c11fd2e767529fbd1ffae362a9bee8a6b092834a74cf19d42852d91dba7c2307a9e515ed4e3bbee25f24c33145485b55b40e0bc491026eabe361c62dce6f021c20bb2df8bcf9ed1d6454e7dc4dfbe991c3b69e5e3ddd30ae06e96ea9d0eae92f86acf561f745e7fc733b5229a612110c77e7b2be4dd9719d0878fb801d3e9f5bd8fdc8d74748bfebbf583e46c62e585279900601ea862258ad2a04aef041cd14984af2621b01eca7e8da784c25dbab2c4e5e38dc9dd88d5ad3cc3871d895b173ed0efe68f60f97061769fe8b26c9658fd283bd62add19cbc6e75f0157b2d5c9b7b99f3f87869b9799c22076933a3c67a395828dbcbeac93212d93e1986a4d6dee836ecccdbbd4f77f63bf6e4e897a0d77780f1c01819763b476adc553a76945f15730cd184f55c3d5102b95361a1c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenble, Inc.
##

include("compat.inc");

if (description)
{
  script_id(179200);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/02");

  script_name(english:"Enumerate the Network Routing configuration via SSH");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to retrieve network routing information from the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to retrieve network routing information the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023 Tenable, Inc.");

  script_dependencies("ssh_get_info2.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/OS/uname", "Host/local_checks_enabled");

  exit(0);
}

include('lists.inc');
include('local_detection_nix.inc');
include('netstat.inc');

ldnix::init_plugin(exclude_macos:FALSE);
info_connect(exit_on_fail:TRUE);

var gateway_routes = {};
var local_routes = {};
var has_ipv6_routes = FALSE;

function is_error(cmd, buf)
{
  if (empty_or_null(buf))
    return TRUE;
  if ((cmd + ': command not found') >< buf)
    return TRUE;
  if ('Usage' >< buf)
    return TRUE;
  return FALSE;
}

function ipv6_subnet()
{
  return _FCT_ANON_ARGS[0] =~ '^[0-9a-f:]+(%[0-9a-z]+)?(/[0-9]+)?$';
}

function add_route(device, subnet, gateway)
{
  var ip_ver;
  if (ipv6_subnet(subnet))
  {
    ip_ver = 'ipv6';
    has_ipv6_routes = TRUE;
  }
  else
    ip_ver = 'ipv4';
  if (empty_or_null(gateway))
  {
    if (isnull(local_routes[device]))
      local_routes[device] = {'ipv4': [], 'ipv6': []};
    append_element(var:local_routes[device][ip_ver], value:subnet);
  }
  else
  {
    if (isnull(gateway_routes[device]))
      gateway_routes[device] = {'ipv4': {}, 'ipv6': {}};
    if (isnull(gateway_routes[device][ip_ver][gateway]))
      gateway_routes[device][ip_ver][gateway] = [];
    append_element(var:gateway_routes[device][ip_ver][gateway], value:subnet);
  }
}

function try_ip_route()
{
  foreach var cmd (['ip route show', 'ip -6 route show'])
  {
    var buf = info_send_cmd(cmd:cmd);
    if (is_error(cmd:'ip', buf:buf))
      return;
    foreach var line (split(buf, '\n'))
    {
      # default via 192.168.89.2 dev ens33 proto dhcp metric 100
      # fe80::/64 dev ens33 proto kernel metric 100 pref medium
      # unreachable ::ffff:0.0.0.0/96 dev lo metric 1024 error -113 pref medium
      var m = pregmatch(pattern:'^([^ ]+ )?([^ ]+) (?:via ([^ ]+) )?dev ([^ ]+) ', string:line);
      # Anything in the status line is a non-normal route that we shouldn't be reporting
      # e.g. unreachable/prohibited
      if (empty_or_null(m) || !empty_or_null(m[1]))
        continue;
      var subnet = m[2];
      if (subnet == 'default')
      {
        if (!empty_or_null(m[3]) && ipv6_subnet(m[3]))
          subnet = '::/0';
        else
          subnet = '0.0.0.0/0';
      }
      # Don't consider subnets of size 1 worth reporting
      if ('/' >!< subnet)
        continue;

      add_route(device:m[4], gateway:m[3], subnet:subnet);
    }
  }
}

var MASK_LOOKUP = {
  '255': 8,
  '254': 7,
  '252': 6,
  '248': 5,
  '240': 4,
  '224': 3,
  '192': 2,
  '128': 1,
  '0': 0
};

function mask_to_prefixlen(mask)
{
  var m = pregmatch(pattern:"^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$", string:mask);
  if (empty_or_null(m))
    return NULL;
  return string(MASK_LOOKUP[m[1]] + MASK_LOOKUP[m[2]] + MASK_LOOKUP[m[3]] + MASK_LOOKUP[m[4]]);
}

function expand_address(address)
{
  # On some platforms the trailing 0s are truncated for IPv4 addresses
  # This is valid for IPv6 addresses
  if (':' >< address)
    return [address, 128];
  var parts = max_index(split(address, sep:'.'));
  var implicit_prefix = parts * 8;
  while (parts < 4)
  {
    address += '.0';
    parts += 1;
  }
  return [address, string(implicit_prefix)];
}

function normalise_subnet(subnet, mask)
{
  var prefixlen;
  var address;
  # Parse out the bits of the subnet
  # 1.2.3.0/24
  # fe80::0%en0/64
  var m = pregmatch(pattern:'([0-9a-f:.]+)(?:%[^/]+)?(?:/([0-9]+))?', string:subnet);
  if (empty_or_null(m))
    return NULL;
  address = expand_address(address:m[1]);
  prefixlen = address[1];
  address = address[0];

  if (!empty_or_null(m[2]))
    prefixlen = m[2];
  else if (!empty_or_null(mask))
    prefixlen = mask_to_prefixlen(mask:mask);

  # Ignore the following routings
  #  ff/8 / 224.0.0.0/4 for multicast
  #  ::ffff:0.0.0.0 for ipv4 mapping
  #  ::/96 for 4-6 embedding
  if (address =~ '^ff' || '::ffff:0.' >< address || (address == '::' && prefixlen == '96') || address =~ "^224\.")
    return NULL;

  # Don't consider subnets of size 1 interesting to record
  if (empty_or_null(prefixlen) || prefixlen == '128' || (!ipv6_subnet(address) && prefixlen == '32'))
    return NULL;
  return address + '/' + prefixlen;
}

var NETSTAT_REGEX = [
  # Linux ipv4
  # Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
  # 0.0.0.0         192.168.89.2    0.0.0.0         UG        0 0          0 ens33
  {'regex': '^([0-9.]+) +([0-9.]+) +([0-9.]+) +([^ ]+) +[0-9]+ [0-9]+ +[0-9]+ +([^ ]+)$',
      'subnet': 1, 'gateway': 2, 'mask': 3, 'flags': 4, 'device': 5},
  # Linux ipv6
  # Destination                    Next Hop                   Flag Met Ref Use If
  # ::1/128                        ::                         U    256 1     0 lo
  {'regex': '^([a-z0-9:/]+) +([a-z0-9:]+) +([^ ]+) +[0-9]+ +[0-9]+ +[0-9]+ +([^ ]+)$',
      'subnet': 1, 'gateway': 2, 'flags': 3, 'device': 4},
  # FreeBSD / MacOS (ipv4 and ipv6)
  # Destination        Gateway            Flags     Netif Expire
  # default            192.168.89.2       UGS         em0
  # Destination                       Gateway                       Flags     Netif Expire
  # ::/96                             ::1                           UGRS        lo0
  {'regex': '^([0-9a-z/%.:]+) +([0-9a-z:.#%]+) +([^ ]+) +([^ ]+)(?: +[0-9!]+)? *$',
      'subnet': 1, 'gateway': 2, 'flags': 3, 'device': 4},
  # Solaris (ipv4 and ipv6)
  # Destination           Gateway           Flags  Ref     Use     Interface
  # -------------------- -------------------- ----- ----- ---------- ---------
  # default              172.26.28.1          UG        1      29789 e1000g0
  # 172.26.28.0          172.26.30.38         U         1        904 e1000g0
  # fd8c:405:7c43:28::/64       fd8c:405:7c43:28:250:56ff:fea6:bb77 U       1       0 e1000g0:1
  # Note that Solaris doesn't give subnet masks for IPv4 routes so we can get the default
  # gateway but not other configured interfaces
  {'regex': '^([0-9a-z/%.:]+) +([0-9a-z:.#%]+) +([^ ]+) +[0-9]+ +[0-9]+ +([^ ]+) *$',
      'subnet': 1, 'gateway': 2, 'flags': 3, 'device': 4},
  # AIX (ipv4 and ipv6)
  # Destination        Gateway           Flags   Refs     Use  If   Exp  Groups
  # default            172.26.0.1        UG       47 2004396211 en0      -      -
  # Online documentation hints that some versions may also have a PMTU field
  # between Use and If so have an optional group there to catch if we see it.
  # Groups is a free-form list of group names/numbers
  {'regex': '^([0-9a-z/%.:]+) +([0-9a-z:.#%]+) +([^ ]+) +[0-9]+ +[0-9]+ +(?:[0-9-]+ +)?([^ ]+) +[0-9-]+ +.*$',
      'subnet': 1, 'gateway': 2, 'flags': 3, 'device': 4}

];

# Tries all of the netstat regexes against the provided buffer and returns an
# array of matches using the regex that matched the most lines
function parse_netstat(buf)
{
  var lines = split(buf, '\n', keep:FALSE);
  var complete_results = [];
  var line, results, m, subnet, device, gateway, flags, mask;
  foreach var regex (NETSTAT_REGEX)
  {
    results = [];
    foreach line (lines)
    {
      m = pregmatch(pattern:regex.regex, string:line);
      if (empty_or_null(m))
        continue;
      flags = m[regex.flags];
      if ('n' >< flags) # n flag is for reject routes
        continue;
      device = m[regex.device];
      # Check for a flag and that the next hop is not the localhost address
      if ('G' >< m[regex.flags] && m[regex.gateway] != '::1')
        gateway = m[regex.gateway];
      else
        gateway = NULL;
      if (isnull(regex.mask))
        mask = NULL;
      else
        mask = m[regex.mask];
      subnet = m[regex.subnet];
      if (subnet == 'default')
      {
        if (!empty_or_null(gateway) && ipv6_subnet(gateway))
          subnet = '::/0';
        else
          subnet = '0.0.0.0/0';
      }
      subnet = normalise_subnet(subnet:subnet, mask:mask);
      if (!empty_or_null(subnet))
        append_element(var:results, value:{'device':device, 'subnet': subnet, 'gateway':gateway});
    }
    if (!empty_or_null(results))
      append_element(var:complete_results, value:results);
  }
  if (empty_or_null(complete_results))
    return NULL;
  var max_length = 0;
  var cur_results = [];
  var result_length;
  foreach results (complete_results)
  {
    result_length = max_index(results);
    if (result_length > max_length)
    {
      max_length = result_length;
      cur_results = results;
    }
  }
  return cur_results;
}

function try_netstat()
{
  var buf = info_send_cmd(cmd:'netstat -rn');
  var route, routes;
  if (is_error(cmd:'netstat', buf:buf))
    return;
  routes = parse_netstat(buf:buf);
  foreach route (routes)
    add_route(device:route.device, gateway:route.gateway, subnet:route.subnet);
  if (has_ipv6_routes)
    return;
  buf = info_send_cmd(cmd:'netstat -rn --inet6');
  if (is_error(cmd:'netstat', buf:buf))
    buf = info_send_cmd(cmd:'netstat -rn6');
  if (is_error(cmd:'netstat', buf:buf))
    return;
  routes = parse_netstat(buf:buf);
  foreach route (routes)
    add_route(device:route.device, gateway:route.gateway, subnet:route.subnet);
}

try_ip_route();

if (empty_or_null(gateway_routes) && empty_or_null(local_routes))
  try_netstat();

if (info_t == INFO_SSH) ssh_close_connection();

var iface, ip_ver, routes, route, gateway, subnet;
var report = '';
# Print routes
if (!empty_or_null(gateway_routes))
{
  report += 'Gateway Routes:\n';
  foreach iface (collib::merge_sort(keys(gateway_routes)))
  {
    report += '  ' + iface + ':\n';
    foreach ip_ver (['ipv4', 'ipv6'])
    {
      routes = gateway_routes[iface][ip_ver];
      if (empty_or_null(routes))
        continue;
      report += '    ' + ip_ver + '_gateways:\n';
      foreach gateway (keys(routes))
      {
        report += '      ' + gateway + ':\n';
        if (max_index(routes[gateway]) == 0)
          report += '        subnet: ' + route.subnet + '\n';
        else
        {
          report += '        subnets:\n';
          foreach subnet (routes[gateway])
            report += '         - ' + subnet + '\n';
        }
      }
    }
  }
}
if (!empty_or_null(local_routes))
{
  report += 'Interface Routes:\n';
  foreach iface (collib::merge_sort(keys(local_routes)))
  {
    report += '  ' + iface + ':\n';
    foreach ip_ver (['ipv4', 'ipv6'])
    {
      routes = local_routes[iface][ip_ver];
      if (empty_or_null(routes))
        continue;
      report += '    ' + ip_ver + '_subnets:\n';
      foreach route (routes)
        report += '     - ' + route + '\n';
    }
  }
}

if (!empty_or_null(report))
  security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
else
  exit(1, 'Failed to retrieve routing information');
