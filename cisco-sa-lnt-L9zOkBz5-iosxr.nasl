#TRUSTED 912f9e8c277222f5578d859ebbd4f10b56dbb9b7aa064478d6bba7ef274c7202072b4851221b37a6dbc04ba8f2e91c314390f771876a21e2c3c680fb53df7a8a9f6ecdd53ebe81d4553d5482b60d7a13f99016b7e2eb55cbe7f9faf5cb8a6abcd1c5190f3b05c4792670843eb55f95b9e84a370564308b7c9306a9bacaff2c17b2b0f16432c7451cee860bd6f1f3e8eca110ea052401ec7ba8e1ae8cfb39789d402daf01d40a080ce653dbc7ddf34b8e6eac025f96a8015ee4eb16a0b5f60debf0d892ce1c6270862b94b1efcfb886d26a1df9d3ac9f8b4d0561f1c8e6457d1214482ac4b0ea812cbdbc82678dba9a9742d483266f26d5192f036dc3e5c63bbc1740a7fd1618ce758965bdb747b0aa42ec914ade63d3747290e76d90ceb3fd96f227dc219150890e9484a64f158e907db463fa8ec6c830de9bf6d0b66c1042d9b209b38e9575d11e93d78e56284050d04e1bdad2794f0ae5e26707c2bc189704127bc9a79d6ceb05e05e1f7cbb9ee1ce41610f1651643c98d8aa9962147795afe095ca4033171e4aef0edf40430c1eef3c4b3ea40c853baceb6bf8175e2dd4e185de3b4e2750244bf7886461a3cda85cfb47e55e0e5fc1bb09e966c3bc5282c5a3ae229613c81601524f59d4d5e09c2f19db15527ab16760a2fecc2fb2d1fa4dc6e7eeeaebcdcfb9183a500d7e40ca5ba612a6abe72a5fd0e337befe420b4e31
#TRUST-RSA-SHA256 749dcf7ab9760beb6b4cbad6886eb8c782fc2fd4c4056c4efa7743753c17aace0b040c5dc85c443e5d1599f24dee2e4e78045478d382dfb2da6593e960f9fac0e32eb743864abac3091a6c00f099e09c3dd33ee804cc103405f58e2715baa7bbbe7f93c88737f9a338020e16e74c74d33726c6c6f44c57d5c0464d5f6088f1668cb1994563f0d5d9770e17b89701b816eb88b6106c0fc58b947ad172f76ec5af82fe2b9d98620173b5e2a79c296ca3b7da1283a3a56c4b2a527dfdcb4c0e94e62edd2218f163d116fe48a9185605f16b2f06c99e55ff673c2e36a73ecf4ea3d1da13ba44b35f5a4b72fc0b62e61858a6b307977fffda063d4840015c2c7769b88d03343fcac83fc895cd010b639633f0d43e568a976532aa71cc130fe4a5b1fc2c8f725b9f2e37a98a1903bfe032a10d6ef29a9fe5fb0e301947b5ec2967cd638cfd59393ca4ea82e712edce09309c35bb6c574261c29a4102b6195a3a17e7a23c76029e4a05198f02f399543135f7103ed894629151dc246ec320ca5eb490af8b088cf35017cb3891e078cdc052ca61b933c395cae8a7d82ff35ff119bb055f2791c9452d83288f46178da79ed9a8b419c516114a1aa86c7a3ceb83db5d1d2f7cb9327c783e1e45b235dbd9007dc6592d062af77181a9e4387a1ff6dfc1711cf0dd9616f6fd1a1e627b5ae9d34952af4873493563f09fc27e87d1decd6333e6
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189726);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id("CVE-2023-20135");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd87928");
  script_xref(name:"CISCO-SA", value:"cisco-sa-lnt-L9zOkBz5");

  script_name(english:"Cisco IOS XR Software Image Verification (cisco-sa-lnt-L9zOkBz5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in Cisco IOS XR Software image verification checks could allow an authenticated, local
    attacker to execute arbitrary code on the underlying operating system. This vulnerability is due to a
    time-of-check, time-of-use (TOCTOU) race condition when an install query regarding an ISO image is
    performed during an install operation that uses an ISO image. An attacker could exploit this vulnerability
    by modifying an ISO image and then carrying out install requests in parallel. A successful exploit could
    allow the attacker to execute arbitrary code on an affected device. (CVE-2023-20135)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lnt-L9zOkBz5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8117bf1f");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75241
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a0abd7f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd87928");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwd87928");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20135");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var lnt = toupper(product_info.lnt);
var vuln_ranges = [];

# Vulnerable model list
# 8000 Series Routers
# Network Convergence System (NCS) 540 Series Routers that are running the NCS540L images
# Network Convergence System (NCS) 5700 Series Routers that are running the NCS5700 images 
# (NCS-57B1-5DSE-SYS, NCS-57B1-6D24-SYS and NCS-57C1-48Q6-SYS)

# 8000 Series Router
if (model =~ "8[0-9]{3}")
{
  vuln_ranges = [ 
    {'min_ver' : '7.5.2', 'fix_ver' : '7.6' },
    {'min_ver' : '7.7', 'fix_ver' : '7.10.1'}
  ];

# NCS 540 /5700
}
else if (model =~ "NCS\s?540" || model =~ "NCS\s?5700")
{
  vuln_ranges = [ 
    {'min_ver' : '7.5.2', 'fix_ver' : '7.6' },
    {'min_ver' : '7.7', 'fix_ver' : '7.10.1'}
  ];

  // NCS540 running NCS540L software image
  // vuln if LNT in 'show version' output
  var workarounds = make_list(CISCO_WORKAROUNDS['show_version']);
  var workaround_params = {'pat' : 'LNT'};
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected model');
}

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwd87928',
  'fix'     , '7.10.1'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  workarounds:workarounds,
  workaround_params:workaround_params
);
