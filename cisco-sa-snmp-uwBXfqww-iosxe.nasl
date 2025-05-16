#TRUSTED 3425117d99eb8d45e02041fe19b28b306f68c2fd09a7371aa5807c4390e73ae01792594785d43ea3d21443e732a9f5eb43d71eab8ebddc375352842197a6eafebfeccad2e92ebc23848fff3ef0a83f95b6c07099de4013d1fa2e20ab0b7034ce6263165ce4f56b98ee44201e64496bc83246693330a4a4a7eafc1eaee5a7810921b91988835390e2d2c8986e12959c176dc4b542bb0fd3a5b1c6e52380c6e391959984a1bc7d441a0fb84293853fa8e785449611485f0f0c78e602ad5d1100f49b4f4c982dc324aed06851f55a42c95c91c6376fe85ce33f30cb4e5d2a5d2f9347b0cf9d0f6c70cc5928f2d187799de3303e68d43c59ce9a0ef572cdc72da82bb8038ec405d09e51ba1de5948422ea218c730de87ad563a07a34669e09c05a77f37c4272be527be01d11ae11bb07ef1775078dfd710b2e4c45d572b5f5c0632e2c274bf8dac6ce1a3a40b642a5c00c1ecb1a5f8a9e9ae062f54e2605bcd876506c60c2066b88f9d9ad831d376891479c972c80c02dc951df9d510f8275a328affefba9980c1088f8065ff64cc7a369ccae085b673cc084c0e6d6b1d87253d40803e3e582b5c769090ded3ae98cc748f1ae113858b90e95b162363960f15893901a9b9414d33997594d8a1c5695b501deb58f6b43e89e1163604574492f68df9de714ddd1e6ea502723306a62c759c4b15459f37f8cf42d5d60369fc7253c6f8b
#TRUST-RSA-SHA256 1f5c5538c190b7f804cb022dbd817faa52175e6267edb11e0933f1ded85b041d79edccfb545ca48ea4471d83607c0e0fce2481fcbfaba675d5eae9ded91e4bf26d19f8078a1d2f0b1d0f9830ce9aa2d1a3fdfb7f3ae8c217253e1ed9d6ad0c9b25c3d1407138ac6f798af982b5e4bf689245f6ae77c111095165ac2a4e9c49501c225c04f21c12dfb0ff17d2ab8ecad0b19a43eae4a738255b2a4c732e04929826cb0dcd1a417237642cd547531605b2bca50060b3397344847c819c169ed8cc7231c6df789023282215c57921cdeb48159ed76fb7c52a39b5026004f0da156c4229dbba4c9d9ebf7cc764bf56bd019627868c83a6391168272ccb03b4527fff34d444a019f918d3d060e2632541dbab63275b9cd9bd62e3b782f9b196fc8be24f111cf9029ffb58b6d74b462d48764411b7d86188180256f27f69766c9fe6251b8d2d395a7cedbd926fffb40c964f7bf190b88075eb457780a39559b3cc6d341d65c3bfd9631232656593b40f032f90fcf9cf119b85c0847b45076eb07c66efdb8e49cfe77daf1a01adb4551d497eb09b23a372aaadcc5a1e1424a1510b20ac899402190bec0c12e7843f31d30b8ef0d8f74a26714d3d10e1ae7b22d97b8af7d934954e2b4cffa658664d20c8ca8fee455801bb13c8f54dfb1e27eb6f9345cdb0a0f9febb3c76b8f09543d6ff6ba28d426e9afc88c283f9a42dedc65970631b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193584);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe24431");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-uwBXfqww");
  script_xref(name:"IAVA", value:"2024-A-0251-S");

  script_name(english:"Cisco IOS XE Software SNMP Extended Named Access Control List Bypass (cisco-sa-snmp-uwBXfqww)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-uwBXfqww
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2d0fc83");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe24431");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe24431");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.8.10cE',
  '3.8.10dE',
  '3.8.10eE',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '3.11.4E',
  '3.11.5E',
  '3.11.6E',
  '3.11.7E',
  '3.11.8E',
  '3.11.9E',
  '3.11.10E',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.6.10',
  '16.9.3',
  '16.9.3a',
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
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1d',
  '16.11.1f',
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
  '16.12.1z2',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
  '16.12.6',
  '16.12.6a',
  '16.12.7',
  '16.12.8',
  '16.12.9',
  '16.12.10',
  '16.12.10a',
  '16.12.11',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
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
  '17.11.99SW'
);

# Due to the nature and the back and forth of confirming the workaround
# This plugin has been determined to be best served with the Paranoid setting.

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe24431'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
