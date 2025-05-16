#TRUSTED 1d31616ac2d7e876a85d90351db166ce214a6e0053487ae864734c314e574d1dd5d4b75b0b60da8420f5e68dd1f7eabf48e9d24655b9fb3a7bd22fe9eb6d3f78852104c450c635212339e2392f5f358708b9cdd480498e7fcdc8dd39c004ecd7d4595b782356090cb2d717ee453a86e648f59d8efa91316702955f851b13b09cf1be664bc958f467ac305acc23779d51c5b33ace17b07afc46c4911c194a31258a5cc36dfb726883303a931a9b25526c918af6f4bfb610182e9688e940f25edda66bb8161e196190cbe31feaf1abdd78245461755ef765aa64f809036ebef17b12f711b8860052b812a869393d6eadab65c07604d8145ddf150f26f06ad6aa300852946c5616d7e850f71e504fa2f0c103c7ea0bda524596f0d3c67bdd1a2abba0d90743a90a602cca1e5ea469b86189312405bf3a8c482b0e53cec178177c79281db060b1cfb6fa80aec8a0dd477a2f62d8eb5f78111e4758f7505a07a4f7617ebbf1744c6883c8e343f8952da2cb94edbd0280bdfbbf3d344f49963eb5f3cb4e2cc63a3a8a74487e2773cad800975f8b13d535f4d68b2c72b42dff4334b35c432ac50029eda071f456625a3e2d3f0725b7d6ec9ff23c46ddf90debdcddc7ed1db562cc624ee2ff7b7316e47b31e77ce182f76cb5a223a1e8649ab0b6b3a5f2a0abc9bf66ccce096e30726a8dbb730f433a14868355cd0511be8b4076b30db2
#TRUST-RSA-SHA256 61e3eb92a4d76c0d4ae089908d4a42f5056c3d714ad0eafa6a1f918f4098fcac71920678d0ee38ddf39f618be720837e3408f601d78f1a912d33303cbdee3404dd9eeaf0d36f87021e25fa9e5d1f52c3645ab4b06742b041ef8f037507d1a47d42dd43d3344a93e13f95bccf137ed984cc34960edea36361cf09487b881390a1ffa614b8849fac77eea34920320c1e58de6e78a1257f41d329b2dcf7e099471e3503426471424ac1b9490d31eafbd4c228c6f82704947d246917726ba7f19e23b3007aafe646695f7fccface8a9e6c1d0d48d8edbf4bc4f2072a9db25829dc2fb5026ccb30c919ba0986e2b282382f725ae1d574205432b0991dc23686a13de7cd17e323caad5f4a725033245cc5fe096ecda5ba132ef251b65ff3f57348514a57c0f0e2673d77c6313dbb8fed563cbfaae022dbfe87604cd2118d691b65e796c22e1b0a84efd487d85f6c6494925501036a12626ec3b3031551a0dccfe24f1b111038f456ca51d531c4d276e2fcab762b13e4e549f8a3f77abc762dc40b81e6642c47966b911f6f4e644388c4d9e2c657b1b9e79d1913a9e23b3a81a14705005eac55a636825288ad828ffd8a3739af331ca7e2e0dfa87fc61e28f5dd8c63889edca00b740b4eee0fd9f1041399567e9cc2d7b8c3a068ecb004707b6f6dd0738737a7fe70c4c6c92b35054d68074a225d4cc7e4d48e5dbc360d3760ce7b564c
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109728);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2018-0226",
    "CVE-2018-0234",
    "CVE-2018-0235",
    "CVE-2018-0252"
  );
  script_bugtraq_id(104080, 104081, 104124);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva68116");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf73890");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg07024");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf89222");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-aironet-ssh");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-ap-ptp");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-wlc-mfdos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180502-wlc-ip");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security 
Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-aironet-ssh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e1aa030");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-ap-ptp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe723823");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-wlc-mfdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?468b6972");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180502-wlc-ip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24673826");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva68116");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf73890");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg07024");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf89222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCva68116, CSCvf73890, CSCvg07024, and CSCvf89222.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0226");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");
include("global_settings.inc");

product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

if (product_info['model'] !~ "[^0-9]+(18|28|38|55|85)[0-9][0-9][^0-9]+" &&
    product_info['version'] != "8.5.103.0")
  audit(AUDIT_HOST_NOT, "affected");

if (product_info['model'] =~ "[^0-9]+(18)[0-9][0-9][^0-9]+")
{
  min_ver = '8.2.121.0';
}
else if (product_info['model'] =~ "[^0-9]+(28|38)[0-9][0-9][^0-9]+")
{
  min_ver = '8.2.102.0';
}
else if (product_info['model'] =~ "[^0-9]+(55|85)[0-9][0-9][^0-9]+")
{
  min_ver = '8.4.0.0';
}
else
{
  min_ver = '8.2.0.0';
}

vuln_ranges = [
  { 'min_ver' : min_ver, 'fix_ver' : '8.5.120.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCva68116, CSCvf73890, CSCvg07024, and CSCvf89222"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
