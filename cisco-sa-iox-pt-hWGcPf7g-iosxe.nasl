#TRUSTED 9879786a11e08732e20bf201107ce6b160eb6ee20073b21fcd8ff049cbdc012e7a52fb362e669890ec644e0938cbdbb089abbcc8e9dc3d69485e4814896309b16163e3034e5dbe344d6e1bd32916f9abd595a7081025a2720e4ebe703eb7408a1c9899fea8dcb5ce28e86ea4fdb6d3f48ace5488cbcaa7b939108f00aa0e2cbea762c132a4cf569fe0bda9acf88756a454818dca39b9adf0d402de5e8f39f1447e10f87f6b17f62641becce405dd55ff87cc340218d060c03cc9b524c3933a73a38f99e9054a82bd57fae48a81b3de78d3ea549fe793ca2a7b8373b5ece5b075206d55891814b0435575e7feb6014f25480f522e03ffb0ba8586e452d176a0efce0f04e1b16f17156d34b5638973748a9228a485cbcd030caebed8e4b9aeb73fa7e735fe451307348404f1fcd5fdb77ec8a82ea1a8d7b1be2fa15745b568bdf9f1a69dec9d8d633c0f0a161c07276c3ac61d1aca4ee68319a743b94df0e6e995c135aeb5cba79c536775c271959e471ba45bcc4cc406c5227cb0b7a1bc6f437c152811a798b94802988bfddb1340a17e0d016d181a2b0d331e608a6cfd147183dcaca0c60ebd15502aadc1e5ddb07379298090ae0ed9e8cdcca431f264e04493e1005b3c72e8fe09696a60c0929b07e2b86329ff69fa0605b1be9bd6dfadbc80f3ba5c4586de75f953bc6c7e7d0c7998880cdc1b68d30b5bea35a2bfe8a47350
#TRUST-RSA-SHA256 9866bd84a2b989776ea9bb0a5d29a1109f1670e475fdeb49b9eade3f14abb43bdb20275d94d6e543b63f905f52fdc11d239f203d680b2aa542e27a9e8681a6e9cbb2d0525a39b03d95bf55bb50bbb1ef8c27c873733996e445981dee1814d9e6c018c1768a959befcf05d1b3eaf00e9d38dbbdac5827b4950dd01404b8e630f5cffe24e87ff95347cc08f745399362b7d3fa098ef0f42d8b4469ba493c03464eb1d905d8299eb7fb7a0d15492bb3aa96dec3c6c6f2fc87b32c3817b36478c467e980987670ba7afd0935f861c30de70a6f8e29549956d2183c3ce6ce74ce35e084f7424c1ef01daf147520345cfdaf02cafca93bb90bf72c78b9135dfb70e1ae216c8c94638ab5838913bd594e4c2a9e9ea57ba60cf00d4c1053f155300a8eb5c3e797f7301b873e1be77a217d54052a4714156a50ea30e3b03c1f1c2bc9174a7e96f851a4d003ce880e71ce2f362e69ab905df5b2ebe3a0d632f9de2c2aa95cbf6837ab3582f3a5f19b49c3f394b8f57d5fd5b57f91cb7abccbe5efc1e84155b15a883bf640300b58ab013b10731e08753e5636a6ee1f042d1fe1fd6704462142bba56e5b96d26876f0c70c29ea05e64ca2da1cf85f233685a0e57beabf72ff4a20fca992e39d9c9fd3a92df63397a6a5e0f0d1f013a0f1b25df0f25ae6297392e7a9422f8eae1c5f742d849fb80d6d8d362852d19885e2934b3a58543756bc
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153153);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id("CVE-2021-1385");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21776");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx21783");
  script_xref(name:"IAVA", value:"2021-A-0141-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-pt-hWGcPf7g");

  script_name(english:"Cisco IOS XE Software IOx Application Environment Path Traversal (cisco-sa-iox-pt-hWGcPf7g)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the Cisco IOx application hosting environment of multiple Cisco platforms could allow
    an authenticated, remote attacker to conduct directory traversal attacks and read and write files on the
    underlying operating system or host system. This vulnerability occurs because the device does not properly
    validate URIs in IOx API requests. An attacker could exploit this vulnerability by sending a crafted API
    request that contains directory traversal character sequences to an affected device. A successful exploit
    could allow the attacker to read or write arbitrary files on the underlying operating system.
    (CVE-2021-1385)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-pt-hWGcPf7g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?529bd81f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21776");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx21783");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw64810, CSCvx21776, CSCvx21783");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/08");

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
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.2',
  '17.3.2a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b'
);

var workarounds = make_list(
  CISCO_WORKAROUNDS['ios_iox_host_list'],
  CISCO_WORKAROUNDS['iox_enabled']
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw64810, CSCvx21776, CSCvx21783',
  'cmds'     , make_list('show iox host list detail', 'show running-config'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  reporting:reporting,
  vuln_versions:version_list
);
