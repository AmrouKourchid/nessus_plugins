#TRUSTED 8fcfb393f6ab770d975fd3ea0039a7be0ac6f1aa7df644cb3a7fc8a5b1a35390498dcca5dc350f3506c1392f6e7c73cbf3fbdb60a97f848bba9937f36682729bd7eae161a5ee9e16a4c690329eed27441a1e5cf25bf5d5ceb0e531384e14bd4779cfa8bf7eca3ac26d09f90a59724bbc22c17c7b15ddc5c74092c9c316844ed9a89a29a8aca352cc00e5b5f0693d2a46719bebe327c6c0980df000e206d1a19eedbad8e82eb0a8d4e1213f99ff785190c175b4108948f5cba9d5a0db7f36603fc891f60f101de19bed175302615d362c9de3acfd929a92c08ef61c3b51395978594d03555d96a455a37827ec785c43a87ecba2244aff4f942ddf3d34218ede0c125fbcbc9bb3fea9ba001f7a4e1af7bd461b1ca97bea546e02323f51f01808954bf7e8c9a0a6d959c6bcbc1a15861bfc3b2a183c51bd98ee7040a2d4d5caad75044523274b30d1220d26311b910aba6976581590ed7342d0a3035b3200290be6120d5562fb4b9e3d0aa00bffc2ac7ee460943cbb00814622491a4d7117768a0f1fbdf210416c08a88e66bb9de4e99641d5ade152840b07afa2e655d43ba87a12fc273ebc84e17cac0e831bc1e934356c045f32317b138595706b4c70de4e892c9683a10a7ed1058da2d0967a8c4ce17679a7afeace50e5bfd2dd472067b7cfa4fdec02096933001932285ae34581bddb6ae5f2f56dc8ee6b26c38b46a54e7b5d
#TRUST-RSA-SHA256 1cbf2292477f089e58d0148ce4df728a6249476f336012a86bb170bedc448308d09b23d239fce88903c9c48cba06f32827940abe174b2af6856bb2a730162625c73efadc31be2575d7032a823bd3c7441302a3deb17e3e062d55918157999b278453917bd47a9771b14d9a2aadf789af423416eb9ede39dcc4984c09a45ee920cbfaecc56e55ff8a4ad50aaa34d10e9bae9810410c1d302507575ab6ed2a47b8ed254c25d1d2e156b8e9deb71723ddac0dfe10fee6c7a9790671423ac6e55e1bbdd3c679e88118cfa9f91661ab3dd02c04fca89fcb568a8099291348656ed7129633033d8870d502848edbab8f9eee8d3a10c45a67747548bfb3e607f9a41be8843fe8315a22cde520ef7d94a46ab35dfc050caf92b9f5720d6465f5f479b180f9966e0a152d68f7b9ebbcc26e1617b4861abe508bd01aa2e88f90562c71d97590ad281713e1a86f28bac075bcf81553363d7fef1920cbc8b9b648ae3ce7efa8c989fa07caf5c3db977b6461de32fa9be0d412133a97038739cff0d88fbc474b77df3df7c12e007c278507a081ed145fb4c31ae2b53e8d8fc0dcbdf5c8dfcc06f9f67bc760307311478859b6b363ea0e3d5541d43c9d92bfc3684816f93a2a54624aa09f33c2994c8d619ebcc206d000d16f5b53e36e0e04b0ac28ddc76b656238b95f2a8ca69950b2f9cebe702bf5201e7ab4081ca2df0f68f6625ea59feb50
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138524);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3223");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90852");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-filerd-HngnDYGk");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Arbitrary File Read Vulnerability (cisco-sa-webui-filerd-HngnDYGk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an arbitrary file read vulnerability.
Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-filerd-HngnDYGk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc271b65");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90852");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90852");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3223");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

vuln_versions = make_list(
  '16.9.4',
  '16.9.4c',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1y'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'cmds'     , make_list('show running-config'),
  'bug_id'   , 'CSCvq90852',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
