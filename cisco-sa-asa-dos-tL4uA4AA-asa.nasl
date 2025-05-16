#TRUSTED 75ec70d2b2f1f32d6c1ee9ab5d7a56296e3b8b40d3387126ab646080ca9ab8bef569ac3f5302081de43be854d44ae870d142ca1929eb11eac6c68f1fb160c30f3f3d948b77df33b01e0d3b6cce2071f6d2603a4e2082f1cb5919fd8e4e57b89fa611ef6ef3248aeeefe255335a1095255cbf4bda0a9cddb3c0543909a844027c57801fd60df894c513a0f3b8f39e6314f36f44dbb5edb749eb45d48318164546e87cd6d2aee03854e9d123ab0a6e6e8c7f495b04ade78237e340301b5a3b298bebf045ee54a6b29608383ad9520bbaf68d368ac5c1e254539da1ababe3ef4437dd07ec10dd3e76fdec7a1740f19d1f58b5d97fee2e973aa76afa26b3878b37a77f893626d7b2bf20dd2e862b1abe463f87f2bcad39b5ebf432e9c7174fc79dda0214cd01a820aa4b6348253694d7ea753a8299d88631a72f1edffdd6cfb03ef84193656667c8a27be836d65b051c0f9ee6dfded94ebeca56954e77b1a32e2a0cb0a69304efd4c313f737ab1b0d7ba15b60586c0fa03163aedf11388e54ad1e56b0839705806076b587058f872f7491568d8334d2c1e440b06f85eaab65d8460ae3895c370880d76cf603661b3fc8499f81e3aa0de4185ef7ef4256b38128c29957a6d6ea1244e02abda7954d433e6c888617478a97d6a00adb9e9c61ac9e3770e0592fa379925ef286879ee98c3db7ac6e7ea6f953f29d3688d45b2a14194dcd
#TRUST-RSA-SHA256 968b001354fabe494846c3f9971b5ae79a7ce97cca9ad9d7d807313e72e53cb1090ae2d493d6374f7426d761e6bad315925705dca2f43279018b52ee1092582c5d011484966e028b5501d44b1fd177eb412a9d452fa8b5a34b0b3f1c2cabea9b651531fcdb57030c800e2c5822d35966f7676a8791713d2a9b44b75eb3b34c2c9aace854a93f912c82185015dc0bd65d1adc22856d11666e25b300923a9a63026d567f6d136ab35729de44d5de18470ba6e22d28796700794f4a1fb6b994bf28f8066e1d61b05439874116e7e496b59d1260b80b45d7dd8ceadc6622e84f7714b094b0d4fe4537f3ddfe0c98fe94aa0941c428aea27932bcfaed7b9734e53754fbb3ec2b6e71741d712d419e92ed88c1a551e0040888d384ed4e9e5cee81130140db649969cffc535d683d34b13203fa52e902e9fd5e57a11da8799db5330daf2b3d2fae17df8ff5046197e300daf39eb486338e60a1b996585daa9e62072a62f6bc3cc969b098907d356b6586c6d9c02a92fbc8d80e6c9a188231bcf6722da506511fff9976f5ed8c8dadeac08b7c6efdcdce33fc1559e460954690d9fec040eddd86a8ce6b6aeb63f4c5eb7fd2c0226264c4cff6343bbf1f007b1d0e20f31e85f7fec7d8afaa2e888438e85b108822ea7875d1662b9f4a04b3a503ad01262e6464f988852c93937b62b0c61dd02715cdd10365349ca75dcc10e4ee1e1048e1
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161869);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id("CVE-2022-20715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa04461");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-tL4uA4AA");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Remote Access SSL VPN DoS (cisco-sa-asa-dos-tL4uA4AA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the remote access SSL VPN features of Cisco Adaptive Security Appliance (ASA) Software 
could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected 
device.

This vulnerability is due to improper validation of errors that are logged as a result of client connections 
that are made using remote access VPN. An attacker could exploit this vulnerability by sending crafted requests 
to an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-tL4uA4AA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3087735a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa04461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa04461");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '9.16', 'fix_ver': '9.16.2.11'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa04461',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
