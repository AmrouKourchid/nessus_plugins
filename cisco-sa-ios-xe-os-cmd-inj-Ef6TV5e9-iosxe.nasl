#TRUSTED 9c352c7dc4b375f089d0018408e1d59f2a774a51dc9373c68c0c10b22a54fded34e708b996c0b7ac0f039db4f888840414ae125bac8278367b1c76276b630a79cc3bdd3c9a6c230adaabc0492bc8312f75ae36ea493ecbc04e77d2a22061db28bb330168cec868d194ae035e01c13b7deb18dacce82df51d034c67c74abf8a3b0298214e504f9fb779028ae714ba7f3acc31c9c9f8f1ad22cdfc82fa0185232bf8345e69ccf59bb6d882609c25b1aa13eabf6d85620d6a735acec3edd905f64dee99365551f93a9bf179f1572426621ac7979f7aa3a6ac6833efe3020120d264eb2ead16b67d7d5ef3f78afcb53bf4f1d470f0f39f77695f99a3cd2b57aee85cfb9ecb19e6b94b01efbd5d8029416588eeff757fbde448ae798ec664554b7a48bfc3f8a1eec3768bdc991719e333e5da3a8c659bad86bb162d68eb5af56527db8d76e129a0ba0a11db7bdfcee946de8b87af409459fb69b398740cedbcd5d98b2d7bf2bcbd43603969768123a4ef3868a7fa6b13a405100dd5e126bbbb5ce92b0b7cde60572ee8cd6898e033a7d5f67c6825cfa306616c26f82386205176320ac4c0509e541c4c2e4189fd79eeedd0d98e244edd21b248a501b8c43c88ed4a380924dabd5516b6eb53cc070f588f68ddb9cb1f80d54e2238425c5d848e53c67c3c3820b1a8f0934e877b1763f399a72e09735d265bbe60800dc8f5c070f86239
#TRUST-RSA-SHA256 62874aa2acc160bceaee85b2efacf40605f667eef0bccc4b390633ee62762d9580c8ccaaf22c3017e4c3ec2be19075ed6a26515d829a4ec6d57e7354d6c8f23334c2c6e508652242ad80c055db6444f8c9d9d7b9444b8b3597fceb3b896a64396f3c135c9f94b9ba6663c9a782cb3880f7068305990332b65fa0572d7d1f7dccd4957ac3b80056499400ed3df78eb11764a696781178b643a89d44f0506edf2c917e7683382e5eea325394fd3c20d62e6e548cd741fe2d435cd73c68fbd2d07b8cd638b69c9e05f32ba84f94f129df961e9c4255d0b91a0910023a4e4aa58be13e405c083f52c7cfe50969cd8858eed95afcf9a1d655307539e888af6a5ea6c079584d3624cc468de3d185db0c09bbba75ee86c83ea4839dbdda948de4142dd093be7beb9545aa02ab52aa32ed8c74aa222472014cca9c2f925dc17159aa4c489f4975036e90c029ffc90b9e8bf37b6874818d695e5f2e82170f465b6b2a0dad6010a451cf21c7b009bdf748a10648454113fffd393de54e27132fc5e8b7fbba2197be5093103d7a37d3847c36a2984c71b41a8dd6f4c4a81650440220c1e2fdaf406b9beacbe05745d5ee6daeb10fcdbc64852ac2c4614c6a4163ec30f795fe5e88afc5fde4507edc7258b2f4ce575cc3268c2fb50842bac161e1339708eb224b0a47a9ef35b486126036c7d4866825a70c676d6068e4611963fdd6e8058ef7
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148102);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1443");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu60249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-os-cmd-inj-Ef6TV5e9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcafafe0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu60249");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu60249");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
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
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '16.12.1z1',
  '16.12.1za',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu60249',
  'cmds'     , make_list('show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
