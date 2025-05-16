#TRUSTED 1a74d755380422f39cd13693d38cf6be7b629e0d49bdfa96867a8c21d990eebbc08062385ab7b603155916c0b826f905f871c5d46098048ac46ac0931a7f0a7914747f5c11a294ced6db198f0282359563b6a8fbab2bb0fa4a7f62e0a57854fb30d76e64c7139a27eff6355846a7fc82384ba4c7a904b73841b2cc2d60b3e36cf9a35be387017fb2cca276193771639190b556f5af8202c6b7a1b5f25cb293d4af92f27b7d32c42f99c3cc911304fa41fde60dc4c793233a2fa6469f0603feb06397d3cd924a0fd2fe792983d168edd53ce5a4f60923af717efc22512caad93d0502d8f1eabf9c0008529b386775073a255e5a72a8624023b6a96b13bd7ded141dd49c439a96b6b619b6e2efd8d32d4d469a8e5c163c9c625fb15d97672d702e598eab0d5d1312a1bc0591cb081644186cb310d0e50116f6cd161442bd8304b3a4b2390620dbf59e859bd3d2261a98c7c4e977f6dde8859c52ae6ca80b988c4d39f7be3698865a280405dc39b056e2a82b88a49e845e28a15abcd9c17b0648605cac3f517c0006751180281fb918e080a1583d5e80428ad1580a8026fdfad7d1943f223d73e15a0f6b1ca3a2908e994d0f748561acd31e112df7ac6224596b0920338e5925337d54081102885a3f52aaa86f3ca36748ef286392d5950ede7cf0a606ea96019d83ce3432fc16cbd2a454879565c140d1589b65212fbbf0835624
#TRUST-RSA-SHA256 2078908157681a691969386cbcad5b55e9e1d76d2616119cf3f043b848db279b969d58092c03554de37f6961379824f5074a1e97e5e89fe1c882b8d0775321b7b51604136c1946c02eba8699bf43375280d395851700222424348c597281d87168e0379213d99a4845743369f424b069ffd682b4ae838e3811c52ca42e62cda7199a9044428fb725aead6e5dcebdb25f3eb08db16c3f58bc2732f72d1243fc7205d62229efc57a078d7d7acb343912158206d1f3ad55ee7fca0c831a5c14a7b1a2de3b245a9633bb34b9acf26118ea113a832ba2f4c225a769340474e08118dea50d0f8a12d173dbb0d0dd66fe652bff6b74deead529d2b81c9e9b6c40f332c10af633504a90a72d16c78fba14bdb7e4372062f34b5245372043f383de7ac16441a3f74e9ddcd2999d29dbff240a3bcaf344cc63a5931ed5128a0fa5ad613524168e95f60b0f6666ddef0311125235e52fa01ac6abac154699c3d41e6ab9ca8d758b404c42628a9f4ee947af9c580ef0c5df95d7ab5a41855ad6de0cc4c89b7c8cc24ff3b54e11a4b38b9d28a4c95af7c679949dfd40e9918341d6a6278b9c18962c16d9ee6ce353b6ae44226254f4577e02edb8ffe66e7bfa88275287aa62a3fd7a043defa7bfa17649a8033fa0b375470d622b793b0b5879f24b16f4ac0629ff6b46e5638e7664f7204c6f6e3b58beffd215b4dbacfab8ff75ccddac2d7589
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186714);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-20275");
  script_xref(name:"IAVA", value:"2023-A-0673");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd98316");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-ssl-vpn-Y88QOm77");

  script_name(english:"Cisco Firepower Threat Defense Software VPN Packet Validation (cisco-sa-asa-ssl-vpn-Y88QOm77)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a VPN packet validation vulnerability
that could allow an authenticated, remote attacker to send packets with another VPN user's source IP address. 
This vulnerability is due to improper validation of the packet's inner source IP address after decryption. 
An attacker could exploit this vulnerability by sending crafted packets through the tunnel. A successful exploit
could allow the attacker to send a packet impersonating another VPN user's IP address. It is not possible for 
the attacker to receive return packets.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-ssl-vpn-Y88QOm77
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c13de707");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd98316");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.2.2', 'fix_ver': '6.4.0.17'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.6.1'},
  {'min_ver': '7.1.0', 'fix_ver': '7.2.4.1', 'fixed_display' : '7.2.4.1 / 7.2.5'},
  {'min_ver': '7.3.0', 'fix_ver': '7.3.1.1'}
  ];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['ssl_vpn'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd98316'
);
cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
