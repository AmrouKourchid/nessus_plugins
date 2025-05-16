#TRUSTED 32d9c64243d7b3121fd2e9056ee7dcb16620f98e14559066243e9cb2cb14f92207aecf4497343db4668b36790e5ddc2f33b159021b790e6fa6b3dcb1ab8c052e33b5d63e49bcb768355fec6398ffc4a0d6abe5806d2a64cbfd53f56722fa97742e48ed5e1f3348d33a5bb3994b1a8fd2bace0c432036d6c8ec8c7cf0e97f8ba1a845b8765c9811022920a350c457d341089d2675f69d92e6652af8b758e578ea784f435e721ad141afae2cb6b2e7c6cc430d45d10f46d9cfe1d5fd0a162bc82e81b4623d94e88d7c7494d534643017db7c13dd40aa7388bb569c583b7b741fc8f6a728f11f7d7ae73694d230a8ad856c500d6fb1602921b1ad36be56f4d517f95961c4257f19f3414f769a0706bf6c0126138f446c1584901ce5d8f7e8c12b1abf36eb9ade3c84e881127ef6e9d1bd091adb9a09f58c8e1239fe73e51365f84a11b15f33ace74abf2cc8a9646d6b18ca8fae70ed0b7da92a3a59d8ec6bdca4c90616eb5b83c8de86fbfacbfd79e8a05a8ee6ecbe2c8a7f9d52fd7ea4dd86dc04f24d24699f50ffe4cdbf3d9d35350ab5ac2acd29ec27892a62ccfe8a9c9d6ea4b629293ea71f17335f6ac73038c0269eea4be2b0c8afc568174ac146f66b12324407bc728f895383315e3c19710f90f6dc4e669943997db7a4ca4bf0d333b3169f71d826c48b6c4dc9efbab7a0ac9f8b502f3519b1bba814d4cb5fc083bb12ac
#TRUST-RSA-SHA256 73ea916101f669c7794b14951e1da959917334eb7a0d31ea1f9bbb9f0e4967c50984f186bdbc10060cacd895b3dfc2ac90ba1370de7a579c87cd9488c6606ea5a35d94d3527bd8084c96d4ea7a287234856518ebe66c15c4449917b35e7aca80ba16749573de4f86b9378edd139a1360b810128cece7b68ba435e2238fa6d6437c8ae171fbdbf627bff1b31f2e9aedc2f504a685184485b5fa8b5e4865ac096b7daa6087560e20a90de2367333268a95468e81a49579357341aa52bc9006d50714512680fe1cd256309f927f57e66efeb916b632ff666b0376af9b000c8582f321751bc2885d1db45c3f7fdbdee246962344c39523a603366e6743bd9bedacdbbf5dc116d92530dc413b26c77e6e1e39483d13783b27d617db7ab06af4d18458b98d5e02eb715c34f39bf280b12be4076bf1341acefa16824e1f51df921f0696a61ba2120083811224c13a7e6581725575f50b42b3cccaae117a75bdae01c5f2979c3c998bfc4f8d65acb816472c85e4861c58bf7c3b843269873441fd5323da7a9a246022c09c275cdaf0a7e0221c46f7725d84530545fed7ee9ca23e05bbd3f9cb1f1b23baf1365eeecddc4b43c3145735f28c206593ec06c9fb9722e8e08a857e9f7ce53f57dd338ebc4906388e8b41a06f607aafbacf6b66c2b692d1183df5fcdc139fcacd019a568ffcb693a16b214e7e6658c25b81a952fe1024662a35
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154233);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id("CVE-2021-34699");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx66699");
  script_xref(name:"CISCO-SA", value:"cisco-sa-trustsec-dos-7fuXDR2");
  script_xref(name:"IAVA", value:"2021-A-0441-S");

  script_name(english:"Cisco IOS XE Software TrustSec CLI Parser DoS (cisco-sa-trustsec-dos-7fuXDR2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the TrustSec CLI
parser that allows an authenticated, remote attacker to cause an affected device to reload. This vulnerability is due to
an improper interaction between the web UI and the CLI parser. An attacker could exploit this vulnerability by
requesting a particular CLI command to be run through the web UI. A successful exploit could allow the attacker to cause
the device to reload, resulting in a denial of service (DoS) condition. Please see the included Cisco BIDs and Cisco
Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-trustsec-dos-7fuXDR2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c00ec9af");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx66699");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx66699");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(435);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '3.3.0SE',
  '3.3.0XO',
  '3.3.1SE',
  '3.3.1XO',
  '3.3.2SE',
  '3.3.2XO',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.1E',
  '3.6.2E',
  '3.6.2aE',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.6.8E',
  '3.6.9E',
  '3.6.9aE',
  '3.6.10E',
  '3.6.10aE',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.1E',
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
  '3.11.0S',
  '3.11.1E',
  '3.11.1S',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2S',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3S',
  '3.11.3aE',
  '3.11.4E',
  '3.11.4S',
  '3.11.99zE',
  '3.12.0S',
  '3.12.0aS',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.4S',
  '3.13.0S',
  '3.13.0aS',
  '3.13.1S',
  '3.13.2S',
  '3.13.2aS',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7S',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.1cS',
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.2bS',
  '3.16.3S',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.6S',
  '3.16.6bS',
  '3.16.7S',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
  '3.16.10S',
  '3.16.10aS',
  '3.16.10bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.1aS',
  '3.17.2S',
  '3.17.3S',
  '3.17.4S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.1gSP',
  '3.18.1hSP',
  '3.18.1iSP',
  '3.18.2S',
  '3.18.2SP',
  '3.18.2aSP',
  '3.18.3S',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4S',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '3.18.7SP',
  '3.18.8SP',
  '3.18.8aSP',
  '3.18.9SP',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.1a',
  '16.3.2',
  '16.3.3',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
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
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.6.9',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
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
  '16.9.6',
  '16.9.7',
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
  '16.12.4',
  '16.12.4a',
  '16.12.5',
  '16.12.5a',
  '16.12.5b',
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
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.5.1',
  '17.5.1a'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['generic_workaround']
);

var workaround_params = [
  WORKAROUND_CONFIG['HTTP_Server_iosxe'],
  WORKAROUND_CONFIG['active-session-modules'],
  WORKAROUND_CONFIG['subsys_cts_core'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx66699',
  'cmds'     , make_list('show running-config', 'show subsys'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
