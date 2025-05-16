#TRUSTED 2ed3c0a8f1c12e7537bb9543798259a8f66ad3549c9361b4b839052024115396d936580a98e959e60f807da3ddfb5905792db96882c955a2a292d7940bd2c66b45d2eb3dcd801ea313b6fbc48f12514935b94d4b87f5d57f1d69b35246319a2f36190a3316ac045392d79ee493fe0420a12a04f196af5c4861613f2a544f547042dd3422ba3a609c92f7fd022bc7029c5297d44acca09e5c1e47bc419fbcdf6ce3aab123b8440c1bccb6939169d8a967c6bfc8f9cb4ac02867ac2154704f06f91a500444d73fe9ebbb80fb4d9deede7ba5506ddd820969e85e1acbc6eae5c7eff3443fecb409eb9f6c0a58e74d73b5381ee0e38a112037ee3cbe627d279c67daf54034a010215577b7c23bda8240578f63f3d07d65ef84df4b1e2e6495ef8e4d9ef7e0f2e4bc4d719ce258fef5ba85075bff94239ed6032513f379312f9f79fb8477ea9e3ac3d465f9d0d926f8d6f517cb59822e1ac4d7b90401c7792c5c22179bd9753b1900531082d6b97dce81e481d5542815ab817f2dc64a4ac337660885feaf259431bcc40b6265ea2b62de4059ba0c24004ec779809699acd8a9903aa7986c09e4b669215b715187fcf328d2ebeece66acbccc7e24aee785781094a04f518012a0a9c0ca8938e7795f5ec50ee4b54a104208eccc592f22b9b914036127a506a13eca8aebfb3a874be6cb32b5561912822c9530938ac95dfe65c656b6be
#TRUST-RSA-SHA256 32626534e1fdb8ae15661a04994194d85e6517506dc2361ab845a300bea5801e9d188f1aa8412092eb76b054bdceb49b9e8d078447316a8a8dd82287941bc48b5adfb1e04fef8c2e32279aa1750d642bcb7bbfc9e3c70d433868aa840347a76adbd4536c9a55e48ef081063bbb65b40d28dfbbdf4219a5591d366c8523ca4e62142f0ba6f6814b84dc6004fde38a6b894601ea4ec7f2eb2e4bc68f8e24d81bc818ba030018d7f27b55f8724a9c8340a37bb65056097f8c4e27061eb21e16f1176bfecb895b55ef6b3c3912030fe6e5b7c7234423409a158d831283810c85612f6348bc2d0591f95f0437ae3521d266c091e29782cb5044cf5248390fe36adb90fd5b9776060a5b0d1fc3ff2110d734055f6994ea419095806ee2065c43b2b95224f7e52261b12256f1394cc839d33ef45b3fab37ca8f3e7d0b4052f450e74ec0a87b6a2c6e616928054573a8201d3ccff9e15067e7b291cd01f0a8c97c5999c1c79287d576c8d3bda510e51741bed08edb7bb625ee1c6c3d46d28a91d189ce9d6b9437d452919ba184cf5becfe92da32418015d5c4c9ede7d71646872a53090c808bba5a7457da52e0990c96a4467e1606d50c2b4be1ee367deaa87025ca975fc7b4b21ab38a24f918e8f82aec28026992e911e9709b1a6d72726bc3c673f2fd81b5bb18b1bdb9c505fb255df77774eec36d1e8af96c2ad5d35ad546a528073d
#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("inject_packet") ) exit(0);

include("compat.inc");

if (description)
{
 script_id(50686);
 script_version("1.16");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

 script_cve_id("CVE-1999-0511");

 script_name(english:"IP Forwarding Enabled");
 script_summary(english:"Determines whether IP forwarding is enabled on the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has IP forwarding enabled.");
 script_set_attribute(attribute:"description", value:
"The remote host has IP forwarding enabled. An attacker can exploit
this to route packets through the host and potentially bypass some
firewalls / routers / NAC filtering.

Unless the remote host is a router, it is recommended that you disable
IP forwarding.");
 script_set_attribute(attribute:"solution", value:
"On Linux, you can disable IP forwarding by doing :

echo 0 > /proc/sys/net/ipv4/ip_forward

On Windows, set the key 'IPEnableRouter' to 0 under

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters

On Mac OS X, you can disable IP forwarding by executing the command :

sysctl -w net.inet.ip.forwarding=0

For other systems, check with your vendor.");
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0511");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2023 Tenable Network Security, Inc.");
 script_family(english:"Firewalls");

 exit(0);
}

include('raw.inc');
include('debug.inc');

if ( TARGET_IS_IPV6 ) exit(0, "IPv4 check.");
if ( islocalhost() ) exit(0, "Can't check against localhost.");
if ( ! islocalnet() ) exit(1, "Remote host is not on the local network.");
var ll = link_layer();
if ( strlen(ll) < 14 ) exit(0, "Not ethernet.");

var udp_dst = rand() % 64000 + 1024, i;
# Check that the port can be used
if (nasl_level() >= 6600)
{
  var max_tries = 9;
  var hostname = get_host_name();
  for ( i = 0; i <= max_tries; i++)
  {
    if (rules_validate_target(target:hostname, port:udp_dst))
      break;
    udp_dst = rand() % 64000 + 1024;
  }
  if (i == max_tries + 1)
    exit(0, 'All the ports the plugin tried to use were prohibited by user-defined rules.');
}

var udp_src = rand() % 64000 + 1024;
var src = "169.254." + (rand()%253 + 1) + "." + (rand()%253 + 1);
var smac = get_local_mac_addr();
var dmac = get_gw_mac_addr();

var pkt = mkpacket(ip(ip_p:IPPROTO_UDP, ip_src:src, ip_dst:compat::this_host()), udp(uh_sport:udp_src, uh_dport:udp_dst));
var ethernet = dmac + smac + mkword(0x0800);
var me  = get_local_mac_addr();

var filter, filt = NULL;
for ( i = 0 ; i < 6 ; i ++ )
{
  if ( filt )
    filt += " and ";
  filt += "ether[" + i + "] = " + getbyte(blob:me, pos:i) + " ";
}
filter = "udp and src port " + udp_src + " and dst port " + udp_dst + " and src host " + src + " and dst host " + compat::this_host() + " and " + filt;

for ( i = 0 ; i < 3; i ++ )
{
  var r = inject_packet(packet:ethernet + pkt, filter:filter, timeout:1);
  if ( r )
    break;
}

if ( r )
{
  var local_mac = hexstr(smac);
  var local_res = hexstr(substr(r, 0, 5));
  var gateway_mac = hexstr(dmac);
  var gateway_res = hexstr(substr(r, 6, 11));

  var report = 'IP forwarding appears to be enabled on the remote host.\n\n' +
               ' Detected local MAC Address        : ' + local_mac + '\n' +
               ' Response from local MAC Address   : ' + local_res + '\n\n' +
               ' Detected Gateway MAC Address      : ' + gateway_mac + '\n' +
               ' Response from Gateway MAC Address : ' + gateway_res ;

  if (local_res == local_mac && gateway_res == gateway_mac) security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else exit(0, "IP forwarding is not enabled on the remote host.");
