#TRUSTED 70f311c837967aa69e0ec838ad064d05bebae0e97c5d7132cc9506ba44ef0bf987d575b952335f84778462e8e399d4442ac8c38c0ab4c91d9bb721f9b8bff5974fb783e7db1bcff40e2eb65c88590aae19cca40f05b8f1c13642b3c9a4f8c7ee5c77442566d69bf7661a39fdaa01a522861529f608bc8bfe462d102cfa34ac6b05b6f2770824ed6416d29ae3dad5bf76a70565bde5d249e1be9f76069988822eabb68345c2a24890d2eceab379bed2fb29dea915f514ca42a491601031afa70bcf8cae601905ff681cf7ed36d04a12526de463b574c034d69f9df6ef412a76a3b60992a69751f5f5cf6a49c95f3efb739a54e87632998da2168b0ba2bada78fd79dae7594980702441d36f37e4f6031e898591ae655f4d301f8995d4de6e7936067bb9e594d6684d819db5c2729d2c9b2cd896bc96a81a5ff80f95d4131309b9dcc0cb00f01d197e21f0c18acb2ab25d4fb4b8d0c9e500c3f68ba65dab910e5f5eab41be7b179d3a3ed740259a57f174db71e91e7c21b329f7638a20b47f196324e6d11e8a28bef74da993c3d54b5e4464ba153d8ddd1c54d1d8c01eb111c229d9b1f2c57d75696475e44995790eb54adfd1456cc99635cf2d09c967234dd3042ccf87a0c35363fff1fdb8bd6c1be625ff37a74823bf1102d005f1686defaf6feb356091d8d72c5457790a410f39463ae0363fec88d285ffdcd249162528850d
#TRUST-RSA-SHA256 67abe8dca8d8ed2c4bcbc4c8a557e5b475858328ed02cbf71c27f716dfd31a323fedafcc91380416e7cb211ab731428ea238886863d5accbfdf7948d5b567acf20842ac25d8b0bfe4c0ce2b244221c52f1417e42033561935ac5314125711d4880b7b41288c2f1785cdbd274767da2960123eca884e4d452b680d507c53c48e0fcf627bc1f2167facb85344434af156d45572e33e38d153c07936cc227afcce757356e447adc5adc5a280b208813dc60b1764fa651326b3658b3bbcf94437963d0facf4c3d423e42f37c547f493047864ea93aac098c43aab578a2f9bdfc6df4860dd1c13d3822a6dfd6579521a2621d072c5f548f2145a5f218b718c6721f7a44741e8142ae2c7742343a12098082d52c655b2477276052a2a413cabd38bd733b0c896ea60e8ef7e0b5ac51fd4ed3a04007ff27df380416ca3addc702c6efb4f5d42c85bdfa1e80d0e526c727620e4ab4caf21209b03162acfaddd816e9b1288af72b80cdddca89e697e66d302fbd48a663dc8ba7b2a802b72e97ce571698a40c1ad88d2a3f97c01c343045d51275c8d777194aacb3670f27b693e5e9bf5e8871aec3c973071d640d517f64596a23bda78de2e63cb14d4c34e8f5c724069284376fdaf17c86ad6c583caa4c9e88e5efdd2d7d900a76d69730cb4c461288f274afb76bbe43321f551a653106c469863fbd077e9e42dce67be9ff5161ad2c074f
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193265);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20303");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf53124");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-mdns-dos-4hv6pBGf");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software for Wireless LAN Controllers Multicast DNS DoS (cisco-sa-wlc-mdns-dos-4hv6pBGf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the multicast DNS (mDNS) gateway feature of Cisco IOS XE Software for Wireless LAN
    Controllers (WLCs) could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS)
    condition. This vulnerability is due to improper management of mDNS client entries. An attacker could
    exploit this vulnerability by connecting to the wireless network and sending a continuous stream of
    specific mDNS packets. A successful exploit could allow the attacker to cause the wireless controller to
    have high CPU utilization, which could lead to access points (APs) losing their connection to the
    controller and result in a DoS condition. (CVE-2024-20303)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-mdns-dos-4hv6pBGf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53fd7c9e");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf53124");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf53124");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(459);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "9300|9400|9500|9800|9800-CL")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ap_flexconnect'],
  WORKAROUND_CONFIG['mdns'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'     , make_list("show ap status | i Flex", "show mdns summary"),
  'bug_id'  , 'CSCwf53124'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
