#TRUSTED 1fdc9fecb5bb4c65cd0eed6ce2e20903d8bfa4f63b8f73c3bba69110d468dfeb01705edad7a73ce7446e60a8bdc9c6494bcdfa05bcf422dfe21507db9ff6a498075643ceacc3626cf9728fe6cccd934a02210436e422260f6d5843e50c8898c326992f4b7e8189fd87298655bbbe70f501174eadaf6512f5584e765388ca7db40f8e54037141e7522abd18d2ba67d5a2a89e8ba600ba5f05c805a64f3a0b31337b2637f783bd4c529af2bda5fe6a1ca1d67ad097701ab2d02006f0a6214a28d9296584755f20a6710d1e5f9b79b04c02f49fa58e23b8e0b63e8d672483039d922c5e3aeb31dd8a354042b004e5929b55c2e926e2fd9302d5d1ce750383c44cba10aa71a69e327c59bd5155914f36404dd7319af254aae6d495a3af98a953b35152879d8ec3fedf3010d5b490c53ca609674bb2f14be57a487181c790d9ac83ddbef280d820cf5aed909b0856d5452672d4117bbd7ec26c65477b9cc7822e940dbb6676a8127d555e1b50370cd5e793dd6b8f35507061cf14a2f54089011883df49184a76df00fd991f4b6d2ef24c15c62637004c7a0e8426c1e67c7f3a7a2d92d019162642e1459f8fd51a0aec8e49c3b38c23323d4531d062466f627ec4db8fde671da85c78ddfd7a7fe93e336faa679c5e36395eb38c71311c5136fdc44260ac0a5cb698e17bf7368875626d828ff9e381444d421a2d2398279fc376fa10ff
#TRUST-RSA-SHA256 884428fdedf83b622a3b161950cb269a6c74b104d0f1f420a62ece85cdafd7bb36f0dd6ef93d1a0866f4cd1bf3e697a03efe5fb386a40d167c37b324c78676b8bc9bac8aa659782dcef2174d3e8e6227ab825020404437008c3b90d92ebcf143a7a4fe9aa3544766d17cfe3a6fb1d647d5a19a6c0fbb9e2add3d17e26733eba6a25f8e18873fe2cf057cc12b6988fb3fbf6058a2531d36972692cda1e647de4e9ebf1cf59bf0c45a243a5fc1ba6b2cd69d1af7c3ed331cfa682664ea5bda58a87ff5096285e98c4f5c2fc09606328658defd481177fcf7d8693d4fcb8acfa6fe71a92ccef6fc298c77589105929b7f4e55dcafeefc552c0e05cf11092616552848be169f8315479fcca86b49c371163c74d8c3671ac9d4434752e74487bf35151ca2388613f5a9d37fa1c3d12fcb10c291173bc7a49505033dfb572e50a2da718f14fd460b33da0e3b9c98ba1b110f9b0c82229cd0613fac04431d070b8ad0ef15216b45e7512e648e086e669285e6cc182aada8afcb84115fda780d4fac97748875e4a34a12d65420c99ba3b49e6f5b43857ed1054de0e6c6d70229a624516972bccbfa73dab6b3d94a681be74892c0d89860068ee72b78a1bf3bb992d04b47782f0b4ce3df7a6dbb6c50cae58f6ec0172789b8adfd79e91ec2cd9ffd0618c19d80a4ed9b0d6514d4377ccd916961105a2454ad1726c657418f1ee6731d632c
#
# (C) Tenable Network Security, Inc.
#

#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(171233);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2023-20076");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc66882");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-8whGn5dL");
  script_xref(name:"IAVA", value:"2023-A-0068");

  script_name(english:"Cisco IOS XE Software IOx Application Hosting Environment Command Injection (cisco-sa-iox-8whGn5dL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. This vulnerability is due
to incomplete sanitization of parameters that are passed in for activation of an application. An attacker could exploit 
this vulnerability by deploying and activating an application in the Cisco IOx application hosting environment with a
crafted activation payload file. A successful exploit could allow the attacker to execute arbitrary commands as root on
the underlying host operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-8whGn5dL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e7a6676");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc66882");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc66882");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list = make_list(
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1b',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.9.7',
  '16.9.8',
  '16.9.8a',
  '16.9.8b',
  '16.10.1',
  '16.10.1a',
  '16.10.1e',
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
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.5',
  '16.12.5a',
  '16.12.6',
  '16.12.7',
  '16.12.8',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.5',
  '17.3.6',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.5.1',
  '17.5.1a',
  '17.6.1',
  '17.6.1a',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);

var workaround_params = [
  WORKAROUND_CONFIG['iox_enabled'],
  WORKAROUND_CONFIG['iox_no_dockerd'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'cmds'    , make_list('show running-config', 'show iox'),
  'bug_id'  , 'CSCwc66882',
  'fix'     , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
