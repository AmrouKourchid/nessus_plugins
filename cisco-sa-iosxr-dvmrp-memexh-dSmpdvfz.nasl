#TRUSTED 6286eefcb20baa6c73d900fa08d4d308235735de5544fb71b2ecc0f2e8590c4c4265ce0aa70cb71314a3dd8d115d53b68ae0ba335f469e24a930cbf4c0f47b78aaf41de079a11b0b8100ae216bd47d34e2603d2daed9826503076d2dfc841f641e9418ebe527e4f2a78a0987959b5606d87cef7717144606e25721eb252bbe014d4efab60f0be350e7260fa24ea717c65d4366a6cb248bc2ed1de61ab221516fcb271fb1f5c16898cba7f05ccf39fee83ee36b10233bdf4baf7fa83286a2ec68550dd0b5be086f6b84b8e1e880ec65e9d2eb6a592df41408234a60e1f02c037a7dfb544ca4e88f58ee46a6d104a0c702a6fe19c4061997e4e83a7f527691f2218224a52101711b67fa2377034098470edb40587cbba9853313a426c10157c13a13a2c5371fda49723fb93fcf3b2424161f66c07ecfe9dd613d24820e9a32ac2d8a70f71bc9354a829dfc72c67f41f1ad87963c19a51c7c32d367ff3790329c37d201c1a977dff986c038efb89b26cc8b746aa34a6d93e2a1c46370e2c08deccd1c7b4772b36cdfa2e25b2d2852c95249f1bbf3448aeba0556d1ad29186af60832c60dc5f42658e53e0185406a57a869ad3f1bdc02636a5cd1b0b94b59b208610883690c4e77b28621671ac0d7282846e68a064b3936272877cbc104f17f6c1fc86538ab24b4322f99d065a5f7ea65f32e8a9845c395307d40d2df4a138f7e2a2
#TRUST-RSA-SHA256 7be8ec72d5bdc2b615c29b65a09d0b6d81dfa1c8c6c72d20b9ce5000348dbb1e559728290203471c034b7745b70178389ca4f89a8fe95da4fc8cd0e38618366eee845e90fc6abe688ed7267dc4af5115af97d1ccba9c18ebd256ed54926bad4325d797f12180263391fb5767e3ba3331325aef14b1c89b42ae3f02081ac67639aaf6107dc911ba373bf18271a348a1527be37507f9b7d53ca7b2aec2d30459c7794b9212db8b1a32daf62aa2bef019dfa0d495647694168fcfa20dece134a5f5a959d82b27beedde34b90bdb2d1872a3b2f0585c6a5e72b374e14c6200ccb3c9a23463ec8ee7b41af280fb4ff64cea118475d603d0c248ec7703bee76ccefda7ea58f08ecef69e138ea43f58dbc5f126868d8348bafad7ea32afce34a8579e5f569f80b03d48e13aeed1f8fbfff78ef2db8623de8bfb3a720c90baf209f82a76eeb62214d9114d897818bc745266e51f251d5564d3f904342272a1702c576f14362b7b768d0a91d3ce1639c4eba5c3c9a4fc01e8e21948c1c0b1206f1fdff1c9d63d005a549c3703ae54c454aad04f5a823ae417b9e7499b14f0f215c8cd2141a29fd26fde4eaca05c7cac542d90f6e29318097f08f2e2386165168f99a11aca5ae410e6912a9deb15c616f26dd905fdb12994d3cb8af1499c252a871eaa84f1e7b3f4efe5f17d85ddfdec7983bcf58016789c7f8fd5110430d4abf99216a681
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140111);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2020-3566", "CVE-2020-3569");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr86414");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv54838");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz");
  script_xref(name:"IAVA", value:"2020-A-0442-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0114");

  script_name(english:"Cisco IOS XR Software DVMRP Memory Exhaustion Vulnerabilities (cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported configuration, Cisco IOS XR Software is affected by multiple vulnerabilities:

  - Multiple denial of service (DoS) vulnerabilities exist in the Distance Vector Multicast Routing Protocol (DVMRP)
    feature due to insufficient queue management for Internet Group Management Protocol (IGMP) packets. An 
    unauthenticated, remote attacker could exploit this issue by sending crafted IGMP traffic to an affected
    device, to cause memory exhaustion resulting in instability of other processes. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number and configuration.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44ee1673");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr86414");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv54838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr86414, CSCvv54838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3566");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['disable_igmp_multicast_routing'];

var model = get_kb_item('CISCO/model');
if (empty_or_null(model))
  model = product_info['model'];
model = toupper(model);

var vuln_ranges = [];

var smus = make_array();

if ('NCS55' >< model)
{
  vuln_ranges = [ {'min_ver':'6.5.2', 'fix_ver':'6.5.3'} ];
  smus['6.5.2'] = 'CSCvv60110';
}
else if ('ASR9K' >< model || model =~ "ASR9[0-9]{3}")
{
  vuln_ranges = [ {'min_ver':'6.1.4', 'fix_ver':'7.1.3'} ];
  smus['6.1.4'] = 'CSCvv60110';
  smus['6.2.3'] = 'CSCvv60110';
  smus['6.3.3'] = 'CSCvv60110';
  smus['6.4.2'] = 'CSCvv60110';
  smus['6.5.3'] = 'CSCvv60110';
  smus['6.6.2'] = 'CSCvv60110';
  smus['6.6.3'] = 'CSCvv54838';
  smus['7.0.2'] = 'CSCvv54838';
  smus['7.1.15'] = 'CSCvv54838';
  smus['7.1.2'] = 'CSCvv54838';
}
else if ('CRS' >< model)
{
  vuln_ranges = [ {'min_ver':'6.1.4', 'fix_ver':'6.4.4'} ];
  smus['6.1.4'] = 'CSCvv60110';
  smus['6.4.2'] = 'CSCvv60110';
  smus['6.4.3'] = 'CSCvv60110';
}

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr86414, CSCvv54838',
  'fix'      , 'See vendor advisory',
  'cmds'     , make_list('show igmp interface')
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  workarounds:workarounds,
  workaround_params:workaround_params,
  vuln_ranges:vuln_ranges,
  smus:smus
);


