#TRUSTED 9f8a933c5cd1b2d0922aa12b4794bb6126df4fb0800a7a5791a63ad00a42263d07aed8f6929c51a912ec8c80e3202d7677570d1633b40c577dfbd55a71f6f58c5a5dc6ac693a8f791338905975561921cc4f95e16bbcbb173c768aa193dd12ba95c87aa3c566295fbf09aa7cc0fb1e54b5704fb8b803591dbf53cbc97ef988ae512d1b8e709b90e779e78f0563a4dd3bb75f4b465e361ca223cc7b513f5ce6b6866d096388a286a67982875d692c8b714275d0b2a210f3fa2ce87de3e46146b6db7f6539ab7cf8455274077afe628834a59964ee6ef34a857484b54befed9790f74cbf676056bf61ebfe3fd06c1185adbc26a43ce7b721c902ad8d2e683677e303eaa35c5769ef93fe6c9eebb36e3c147e46533a22bac3440742ac67dc418fb02feb2c4c101a0faac8e462741325558d22fc4c0d9a85fd3fc7bd3c48bb0fb50b86e965d16a490286edf5cf960d4892396c05bdf12dc0ffc3630f7c3655db648272fc1364d0e51778457af7040c12ab8b1df93666bb60fe9a09cf979e0f81bd1c22b290a25d36ed468e1daa2a537da2107d1a8abdb8685cf67d9789600a3f1109e440e94ff58eb544cd385e99e7602a3c03232c15b45ef52a2758fa68a1fccb931d141e530d7563a8dbe6f11be11da9ad26ccdfe158a72ce2f778a40e3999d9d14ee564a133e03946f0002576ba86a7c15662d854dc1349a2cc9ca6d8733f3f56
#TRUST-RSA-SHA256 b163719dc461458cfdbbef379765a7500f549a960281d87cdc554b185bca1c1553a4c9cb3161c1f0e2f6b421bbf7ce2f65701fe4d0ed1f347c4a7d1790ba80f2a97d7d2ef29ed29fdc29868cc90bb281e42998065eda91f2827c61b44328ef5365d2a86e57b164d5200237eac8f85856ec795a71b58508bb2070c67034d6158d0099455b1597a39001f908bfe2d19c2debf05a46a351b0f3b5dd7d1ed3ed2c5ee8b60c1bf0339387a833fe90b16ffa1f509bf01a85937877258f17a7fc38fa33e5ac02763d1c5869a067d7d13cde6c36b16e7481211644df83c6351d1f875abb3e55a3ac2b34682ffcc5a3b249465430c38002f1f39d1f8803e4f6c58530cb3ed086e8086be49da4482ad6a5f9d2f2130747d2ad07188c491b6dd789e2d7174687c71405b2e653aabbbb72faaf8c692c795ad62110113de62c40817e9e036cd9b25d9be84ca5093900c9f56782f3dd41582be13540adef3fddb6f1d153d81d977ca5dc3b2d240ce5734b94be18cf8af43193ee978ff65e395d074225e48dd4fbdf8e4172acc2d717854f089526ac93a562b66547b302e16897aba8b2770dc0ffff638107f35827d10d390ad830cdd96e0512af4084dbdc10be61804231f90b3807f6153afb7474e5e58f1e657ef02507220ebc6a7ec3cdd510dcc90fc6c5293d300062d757da41ebd771bd058659a0d3655b479447a680c27cee8331c5451e1f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128421);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-1752");
  script_bugtraq_id(107589);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz74957");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk01977");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-isdn");

  script_name(english:"Cisco IOS XE Software ISDN Interface Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the ISDN functions
which could allow an unauthenticated, remote attacker to cause the device to reload. The vulnerability is due to
incorrect processing of specific values in the Q.931 information elements. An attacker could exploit this
vulnerability by calling the affected device with specific Q.931 information elements being present. An exploit could
allow the attacker to cause the device to reload, resulting in a denial of service (DoS) condition on an affected
device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-isdn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6adb46b3");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz74957");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk01977");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCuz74957 and CSCvk01977");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
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
  '3.9.2S',
  '3.9.1aS',
  '3.9.1S',
  '3.9.0aS',
  '3.9.0S',
  '3.8.2S',
  '3.8.1S',
  '3.8.0S',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.2aSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.9S',
  '3.10.8aS',
  '3.10.8S',
  '3.10.7S',
  '3.10.6S',
  '3.10.5S',
  '3.10.4S',
  '3.10.3S',
  '3.10.2tS',
  '3.10.2aS',
  '3.10.2S',
  '3.10.1S',
  '3.10.10S',
  '3.10.0S',
  '16.8.1s',
  '16.8.1d',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['isdn'];

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCuz74957, CSCvk01977',
'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
