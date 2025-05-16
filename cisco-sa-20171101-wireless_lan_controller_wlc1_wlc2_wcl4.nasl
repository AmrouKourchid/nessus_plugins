#TRUSTED 7db49a55697c0d0011df6b8cdb5c66ae5e837a504802fc51c61c789a1190b8701fe33c492fbcaf494587defe906903bb18c6e2f9645f0462ac7a1570183957d2b1b2bfe99f019d526c957d213471e44e82671bb943e3f166cab16211b193e792492d2393c0bdd4e0cfad2cfb886dcb11c332c4504f4b61602e4228f8ffda89d3e33d98332def1b47d8b14ee80329778f6c43650cf4c04126cfdfb3ef575c91b6cb6df47aedbf5eb8406d0e2d6a0ffc9bcc056d1a66f6bad8491fadc1bc56f7940dc4daf07c021bd258973d66a61cc02fac6126e84dc2a496d0d9941f7c1059f19f65c6f79fbf3a26d132b0b3d05b58f49e78779bed07e45093497180287a4ec88482d8f511f0193ebea20eb7eeeb38ca8f0e247548bd0e9b3effb757ed9fd8d2a59b000a834dc7e163a17577024c168e46fd5f735f41e6e0707e51a2e4d4c92c91d77ce5d8f5b2901be17fd678b1205642a4b6560467a108d4d152e35c47c299671d5a1e1110b51d772850f0a60abd15dbaa6f0617b46847387ad73c0ebf37d510fefbc456df4b377fd821299b6985060605b72b223e277b99d8362eaa218c46bc6dd3bdec060224e1489d44ececb973a75811d50d6d7f2f15ef2093f7ccca8ae89de0b494327930fc65e8c1cb4279171031207cae50066be035b6d75dd1482d66038e289ecf69410e43ec6ee5c803ff69502b6027e632ae55676664c4c6836f
#TRUST-RSA-SHA256 6e588ceb4839580886ac1d99c54e6ee7b7e690708b5b7d1fc7ada33063730af88d3ff9cd9d730c021beebb94bbe86ea18426c1727f1bc500bb99278711c9c91b4cf6f5e33b5d5f6e225fd0898ac2db3a4d9ea065036fd98a72ab3ced89970579d795fcbaccf2306d6b8c8483de19fc53b8f71a3284e0154a481cba66623b0ec2c86297ecba6214136a26cabf02063901d63fa80ae61353928be7158e16d1646ac88d16f26b2b68f6ee7caeb765434713ab9d77398395cb2b514dba24004f7f3e45184ee98894c295611fffa62641b5c79df1f067f610e5de7b3e58a29f101c66dd1efb65ee5dfcf1db8bb2006b27871b3fe821aa788635630cf4889e5b480ace75fae8f897350511f74667baf5b2a0c0f02674729794037d06321dd0a2b46dcaa479f79f8622544e6017cb9372188a76abcc71c77579379bacef516c7d258025a9aa2bf109e8fe7e5672b4e2be5656527605e60c9175d0d1089856cdbde6e34a4c1b1440161ec0986951975ee9658c90a687d3bff0aeb49f38c7f40e88be606523d6ee5b65317c1b2de803846767b4e319594cc3b2c5489f4a1cc2c3a5082946708d27205cab682421ec02379f096a5d3a5491138cd1eb445fc70147269b8ebf079941e9bbb05c8a60189db488ba30bb741cf3d9ebff989a9c0b6b9c16371b7cd672dd5e3ef315979c5da15e7ad600ceed49d4b0990aac3bf0e325937da830ca
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104460);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2017-12275", "CVE-2017-12278", "CVE-2017-12282");
  script_bugtraq_id(101642, 101650, 101657);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb57803");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc71674");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve05779");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171101-wlc4");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Wireless LAN Controller (WLC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Wireless LAN 
Controller (WLC) is affected by one or more vulnerabilities. 
Please see the included Cisco BIDs and the Cisco Security Advisory 
for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b1ceb09");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc71674");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?756f0476");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb57803");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-wlc4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a20a37d3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve05779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s)
CSCvb57803 / CSCvc71674 / CSCve05779.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12275");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Model", "Host/Cisco/WLC/Port", "Settings/ParanoidReport");

  exit(0);
}

include("cisco_workarounds.inc");
include("ccf.inc");

# Making this paranoid since we're unable to check the config for SNMP
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var model = get_kb_item_or_exit('Host/Cisco/WLC/Model');

var product_info = cisco::get_product_info(name:"Cisco Wireless LAN Controller (WLC)");

# Only model 5500 is affected
if (model !~ "^55[0-9][0-9]([^0-9]|$)") audit(AUDIT_HOST_NOT, "an affected model");

var vuln_ranges = [
  { 'min_ver' : '7.0.0.0', 'fix_ver' : '8.0.150.0' },
  { 'min_ver' : '8.1.0.0', 'fix_ver' : '8.2.160.0' },
  { 'min_ver' : '8.3.0.0', 'fix_ver' : '8.3.121.0' }
];

var reporting = make_array(
  'port'     ,  product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvb57803 / CSCvc71674 / CSCve05779"
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
