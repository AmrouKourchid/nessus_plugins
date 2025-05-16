#TRUSTED 9b3aedbf34e49a4b0e428ab09b31611a41e52b4b72561ca9745694717e6238b6533382f40e2e8db7d31ac280cf968c5e5319dce3dbf322e5a88684e078b06a6012759e26dff06f41684e8567f462c68456bea6df7928b4768dfe17a8d1557760e732caf66dd95bd12576a604381546c02c015fda6e7bcff9b5806570862c0664098a189a25fe9c2a02e68234fb89e7a30654e2df4b6de40f21b5d5ca6d743c4b1ecc09d2316cf44758ecb849f5f08e00f0e11f27e02518fc26aa14f2241487e96acaa121cec9a0de3eca6c9eccf775d8ba0a2369f8f98926b5cc7515d1720e8932f28be508c58c1b4ab5ea59d70f58332d54ca22c9875d94aa43e091df45af6a5cce33b42cadfc181f95d096c4bc6a6711c257b6e56818726ac858a0cce22fd635796eec06ebde4934f17f0d5b56ca1cedc2d50b389500e7ea8de75efb5ec09331dc90385fe39365bcfcd6523de80f774602daadc7ddb521373419e7fe2363885b181aa8f7e1e0102e5faaa823209b797e32080a272e0340752c5304b7a2f778e2a89e59a02fdd8f748b25212eb32336a9c5ad72588115865d30ad70b8900ae5483c3f2ae463bf0eaa41bd5d76ec0063316ae7ec47af66500b3a0caf352b65ca0fc26ae70d9e6c998e3be6e9736204a1134a10b3c39b2438d95b63f1d6795aaa6657be6fea60f5c9b831ea2176e817354190b7085554e6a9185259e6583b3680
#TRUST-RSA-SHA256 8a531d638e560acd353eff218c2999681ffa3f7f7bc66819e5178a192815396a95cb3d4c40c1576322782bc8adbc0401014b73284fa7299d478c508b64ed6fb067a07bf38f98182a0ed17e1a396964cfe9c449d4634e5cdd41b08cdac6fafba49f24985645b092c2e63f8a400cd7b106050e58aaf45977dcf264b84d3c0c466dca02d75480fa979f53e3b7c7844b47727bd10478a98721ef5c2d1f05204a361c2f9b66bb8ae11e90e1d225a22ac6a994451ce1cb13d8828d0918ba0118bd33c88a61da5eeec3d66b229fadcc3b979b6457d965b3535e885f41dee373db4ba4bd765f11fa66effd030cb27d8342a72e8421be9e6d0eb0b5c2a4261c13001df1f3301e7e10aaa102233c52d0b372622186f9c33ff86b0c83b2de15657f9b5dbe39889d4c76437b2c491343790f59f98bc7f302f97a4206c4780e78952132cd61ee32f76f566573df202b489788eb7afdf6801d655fabae0324bb2951e0c7633f61821021bebdab48c72d7309a25d9108a115fa615d11a642589cde168774cff22b44993977b313e41833561037e98a557e41e95eed5891e241fb64ba929bc862b5d9e4063e1c1f51551f597d739a620106c4cc3a3296446eb918440f520a29219e6b78db7f5fac642f271e4a5a2c0e939900de5a20a313f3bb1effff69ad03a30fb1e10eed50b40919a6ce10311177f703e2b28218ab1f97a5da1c42851dbbf2e0
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);
include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(35713);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/01");

  script_name(english:"Scan for UPnP hosts (multicast)");

  script_set_attribute(attribute:"synopsis", value:
"This machine is a UPnP client.");
  script_set_attribute(attribute:"description", value:
"This machine answered to a multicast UPnP NOTIFY packet by trying to 
fetch the XML description that Nessus advertised.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

  script_exclude_keys("/tmp/UDP/1900/closed");

  exit(0);
}

include('byte_func.inc');

if ( (!get_kb_item('Host/udp_scanned') || !get_kb_item('Host/UDP/scanned')) && !get_kb_item('Settings/ThoroughTests') ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0); # TBD

var port = 1900;

if ( safe_checks() ) exit(0); # Switch issues
if (islocalhost()) exit(0);
if (!islocalnet())exit(0);
if (! get_udp_port_state(port) || get_kb_item("/tmp/UDP/1900/closed")) exit(0);
if (! service_is_unknown(port: port, ipproto: "udp")) exit(0);

var hostname = get_host_name();
if (nasl_level() >= 6600 && !rules_validate_target(target:hostname, port:port))
  exit(0, "Connecting to host "+hostname+" port "+port+" violates user-defined rules.");

myaddr = compat::this_host();
dstaddr = get_host_ip();
returnport = rand() % 32768 + 32768;

data = strcat(
'NOTIFY * HTTP/1.1\r\n',
'HOST: 239.255.255.250:', port, '\r\n',
'CACHE-CONTROL: max-age=1800\r\n',
'LOCATION: http://', myaddr, ':', returnport, '/gatedesc.xml\r\n',
'NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'NTS: ssdp:alive\r\n',
'SERVER: Linux/2.6.26-hardened-r9, UPnP/1.0, Portable SDK for UPnP devices/1.6.6\r\n',
'X-User-Agent: redsonic\r\n',
'USN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n',
'\r\n' );

len = strlen(data);

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_tos: 0, ip_len: 20,
   ip_id: rand(), ip_off: 0, ip_ttl: 64, ip_p: IPPROTO_UDP,
   ip_src: myaddr, ip_dst: '239.255.255.250');

udp = forge_udp_packet(ip: ip, uh_sport: rand() % 32768 + 32768, uh_dport: port,
 uh_ulen :8 + len, data: data);
if ( defined_func("datalink") ) 
{
 if ( datalink() != DLT_EN10MB ) exit(0);
}

macaddr   = get_local_mac_addr();

ethernet = '\x01\x00\x5E\x7F\xFF\xFA'	# Multicast address
	 + macaddr
	 + mkword(0x0800)		# Protocol = IPv4
	 + udp;
filter = strcat("tcp and src ", dstaddr, " and dst port ", returnport);

for (i = 0; i < 60; i ++)
{
  r = inject_packet(packet: ethernet, filter:filter, timeout: 1);
  if (strlen(r) > 14 + 20 + 20)
  {
    flags = get_tcp_element(tcp: substr(r, 14), element:"th_flags");
    if (flags & TH_SYN)
    {
       security_note(port:port,protocol:"udp");
       register_service(port: port, proto: "upnp-client", ipproto: "udp");
    }
    exit(0);     
  }
}
