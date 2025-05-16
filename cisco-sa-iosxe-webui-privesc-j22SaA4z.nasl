#TRUSTED a4828d9778477b8a6410ccf0b55cc54197e847dc6feace5c424c7c3e26ee8429d80f164476bf291254b049b8ef605389d8f81b9517f7d449f6b5bfd44e8664e2ac173a4e279171349959d2e2cc1f26a30a4dd5153256c1ff67c2d97abe62216a82359374ed468dcc3b5729689c8e4b49a3a7eb3a72d1592330784371cec7956f9c12b986454ab0f9287bdc593862f24cef753b677907d553f10060b5ddb2eab2bc01cf08d34169d07d124c84e9960601ed31ff890a7a63665021878f4054680a78196fd7fc945fa0b1c072bf19281f567b4d695ce0fd54f98d04f9aae9c21e0d05c0c86190a8c574f3694dee873b95a66e4c40adb6246deefc40e60afb6f5a8571a3729ec5ceeec82aa35b05985b49333bea81456ffde2ec5d4dfe31ae8e17e98d8ad6d5d4d3633973296b581d8835bfa6edb2ffd9cfacbbe1b0412ee488103774af6b1ee8153707334db9a7eaae340dba70e33d2e89e04bdad36fb951213355dcb5568773e9380c640a76326ee9c19222f9f18bb9797a53914b208d0561b36bd0b6d38361f1b87deebceb342aa005255ba8e8f64446195819dfa32e25eac67e1e90de7f6ab8c1735c7b775d39d3677b3898d871aa069ba95a264e07a53eaa73b2841b6d71ff134a722039e9046e55c88da068e00a699fb00d27f888105332cf346f020271b3a26723b55648d8ea99d92850d7828fd3c213b62e654e2dc19a52
#TRUST-RSA-SHA256 8218ce0f7096822ac0f9fb9378b74073247bc8b196d2605caee90fe4f99529e309d8487d5e220b82ba42974f09e58635548a4f8254c9041d330cdf4c247bf6f4e140568bfbfb4bd40a6492f4c119877815597d87e637a2d95d582e2a3cad9ece3b8412d05e780aaea987634f14f2f67209edb057ca6653fc893befa70ec2252a6eaab003d561f64fdc9654fa0860738c5374b158c470620876dae0ed295a3012ef04f139c7dd0731557390556a2e5013d5fbef0556eab311a3ae4154b6d87420da764ba6d76fcb63c0a5937ebd926563935c297ea946f20152476e958813fe89c7841a0038f2ab3511e9cdb84fdd3818e655569b87355c8e1b7ca2a895c238f47e8a31652da731f0d643c77dc1f4bdca9d1df63011ac66a3953dea7fcc3e1a60226e0e2311c3ac6519410186b5ed6767a8182fe6031bb63ef20416b9280cdcea63fff89f83238eabc5aa5419819d19816e2195128e452cd19e7a4cc78a7966733b3496b4fdd9d36f0ad8e537af0f5815259b3b27e86c694474f2e7986050ac27deacde4271784423bf6bb9bcff3e8fa49f8410fe92f1b9db779ca36a81bdbc0cf94b5bb1881d4c6100653bb687a4dcaf4635a687ff89c4d4e7a7d4d2851e92760113da55d6a9813a45e4a73a3336a56af4b458ff70af7b33cf575150dcf032017a4be0b1f2f87f97c15a4fa05d3120b6d93a885bef666c79cdfe25ab9926792a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183167);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2023-20198", "CVE-2023-20273");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh87343");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-webui-privesc-j22SaA4z");
  script_xref(name:"CEA-ID", value:"CEA-2023-0053");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/27");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/20");
  script_xref(name:"IAVA", value:"2023-A-0574-S");

  script_name(english:"Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-iosxe-webui-privesc-j22SaA4z)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web UI feature of Cisco IOS XE Software, when exposed to the internet or to untrusted networks,
could allow an unauthenticated, remote attacker to create an account on an affected system with privilege level 15
access. The attacker can then use that account to gain control of the affected system. For steps to close the attack 
vector for this vulnerability, see the Recommendations section of the vendor's advisory. The vendor (Cisco) will provide
updates on the status of this investigation and when a software patch is available.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2eb79c65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh87343");
  # https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-dublin-17121/221128-software-fix-availability-for-cisco-ios.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ced6a6e");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20198");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco IOX XE Unauthenticated RCE Chain');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var cisco_bid = 'CSCwh87343';
var smus;

smus['17.6.5']  = cisco_bid;
smus['17.9.3']  = cisco_bid;
smus['17.9.3a'] = cisco_bid;
smus['17.9.4']  = cisco_bid;

var vuln_ranges = [
  {'min_ver': '16.0',   'fix_ver': '16.12.10a'},
  {'min_ver': '17.0',   'fix_ver': '17.3.8a'},
  {'min_ver': '17.4',   'fix_ver': '17.6.5a'},
  {'min_ver': '17.6.6', 'fix_ver': '17.6.6a'},
  {'min_ver': '17.7',   'fix_ver': '17.9.4a'},
  {'min_ver': '17.10',  'fix_ver': '17.12.2'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);

var workaround_params = [
  WORKAROUND_CONFIG['active-session-modules'],
  WORKAROUND_CONFIG['HTTP_Server_iosxe'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCwh87343',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
