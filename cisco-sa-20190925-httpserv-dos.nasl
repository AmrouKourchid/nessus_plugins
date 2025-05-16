#TRUSTED 71cab16b752eed7d0a8db554b6bec60281f9c270b74dbaf47be99bb118d6f10537ecfb7c312bcb6670b78de80e588d6f3bcc02935358d90bdc4241b845287afed8d0a9567150bf9e38ce50f3cc3ac9ff2ac82addf77f42a816365472de137a800515c3b128f97fad6dcbcbd4ae04a5d271c53246523287247a36c783b552436c2b2ec09a719ec2beced2f5d5e285add317b6cf058546b59d2d54b2beb3689cde946de5ec7ee1e2e0392f799712d195727aafd727181eefa54d7b98ca1141c6239112c0017874b5837d2c9fc7885678911cfe49692eb240a0d308b8fdd249ef44db3d6444b255b7fbb48257b3c1eac4a61e39cedf55777b4c7e6a7bb9ee927657c22aa08bd3115ab8a3508ecf63a8be80e9d8866384165ff0d4f736381516821b596f820a2127ff00e9421450c5a83f6bc543254f066d8d9ed2b895b4ef8ae7a69afdec25fccd8dc1e975b92dd5c62bcfb78403057cd88b724ac642c5a93e967100136150b5306c07b73a2d73c53be3e8326313592296afbacddf8b5abeb46bf6accb111f72b95ca36952c51169edf7ef62fcdd9cfcbb7faa430ed8cf1812302d3f84f67644a7302a53b735a6ef96001e0fc0772ea5f34e0d3bb37255628f03710e0164c9893e1f85c56d087ed5d87cf3f12ab814f4b1f86ead39829cafc5a068e8cb77601a38e2294045ca26c54586a1a1715d09ee9ea74da2c1d46ad1a5411b
#TRUST-RSA-SHA256 8576c4822ce67650b87c7e428838b819e6eee8b4f6ee0cf3501cc517e1904f619f52fb5bb7790430f0a3f8bc98bfba410edee5a2c69ae6d69d0454eb1fa0e52f886df25a426aea2b43596bda215c1253141677db9680dfe85bb2862ed724e1932027820a6d9cc71b009f2acaf69be26999ac07d957d46f21d433587f139e34f027ff440db19f2bbab952738a4d9adbeeb56f094e245e3987f142a0fba395b55ada59bccbf138e33d23ba33e59ba286bf5525af7bd4e58fc42eac80f37ceb6ac4c7bca8a072a0eb0beaee64eed90633d022466a1a895bffcd424ef667754a1f52e9f428758fa9e5c3756f9371354c6ac360daf5a0a737f6a84e97b32d77d5a8ff898cdbaf2de6acb1e1e99f5b81ac1682196e086e898b53bc1a19318c7ccc70443b1eab04d558d3b354c52256867f9cc4ef38910931af18ae0ad45c3664d33f47e00603504cae997fbec23d319185694fbf7fbd663008f7870056cafe7367d67f6083ee656a844d34b1a908b0dd24a5e993217111d92ca517613078c8047ca59ea4413dd8a489488dc8b04c3dbb362ab8500d471d1353aed6d3b49d3c9c578930a35df31f5f54d3b44db1cc0d074492fc885138ee257777e13306a77211f56e26af140321703c8f54e6eab5dc0b65f99a2e858237bf7788cc3ccafb2592e18367adb93bf391bc5819723285b080bd3750d5dc7efa336607e1af8f16498bfa22ae
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129591);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12659");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn75597");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-httpserv-dos");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software HTTP Server DoS (cisco-sa-20190925-httpserv-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the HTTP server code.
This is due to a logical error in the HTTP server logging mechanism. An unauthenticated, remote attacker can exploit
this by generating a large amount of long-lived connections to the HTTP service on the device, causing the HTTP server
to crash.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-httpserv-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?460abc42");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn75597");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn75597");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12659");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.2.0JA',
  '16.9.3h',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {"no_active_sessions" : 1};

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'cmds'     , make_list('show running-config'),
'bug_id'   , 'CSCvn75597'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
