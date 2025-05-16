#TRUSTED 49a1288144d7a60b24fa7d5729ce577540803bf4a5a4a4ec63e5ea3eed06df787a3ed01d9dea24e68845bf1367cb9a6a83d29fa07d0e84cd8e8d6d39bce65a4a268a727b6cef14986bcf50f6b2a1fe9fac8eff9493fcc3eb60d70eab13ab9e97a53fc42874102f74f78ebccbf74c11d3e44b1049a12cf6af20cd25c4a9bde022c6e75c03500044e170a7787dc97d4571faec96419fb26592b9d9a8c390543d82789664e278bf26dc1492de7fc414052c5aa2cc5ab8893f1913923d673c018b8c1aca60029595169f574a30debc12b4cf285db905fb113397d6ca4f25aba73b5ed6ee268dd0cb193fd08159f1deaeed2d69678bf54dfac434d0d8d83dd0d828428baee7613ef3631af57db7607562e798d8750b750f637283df09f9ca836e2d4cad1751bd49e8a79b7aa06048f3f36d21c1b889d2ae69f59c7724427dd95937b60c32315a2e0f1868639c24aecc2b7f379cab0e7d70e21fdffdb5609d774a46026fccb6de543a7833d2b0cd18e2a3f139eabbc917fc65b230f17dad039849c607d054e3eb451e60e580a4ed7cf8c2c16ac0fbef59535d64225bff6b71413e739be3686054489529a405ad296fcb973595f67f76a6aa24c733ac7be18d1fd2b2c11bd76125bc603a40c2191eeffac13adb004ff4393448b9df0a727eebc092db5c65545ef0b0fd45e41db959b24e000cdbf83ff9a42da7881b7fcc1e063c8dc42b
#TRUST-RSA-SHA256 9df45d3192e06ac0effc66e4fa4de210e343e9f818e2b3f7956876dbf05837e2e977f68fea33fa347067ed633ef2b64ae36b967646f5f40d4d9dc5c445f443ff6a5572868df684cd2539059060608ba3b94aee5033af7127a3582c8c951c716eedc241b31e5c051a384a25bb31fda575e8cf1802ece8c3b1aa722b2bda40351664679b7745e04a3626d01e17e7f3600cd2b6b4db40340ace631a0e4716fb926e01398be247a9291407917c5848d320ca831f07bd83b6736cfd9b0191120ea3defa38b54c21ad105d1413da8cbba6dcfaaf2c6e4f73805d2f74f138efb987888c1d2898d9b8c60aec339aa1e279fae032670a795d9b8821f07881b69b87f10c80b535ca428459c3bdbb11de19b6ddaeb8522b5be47d90b9e79ae9e33b8513de2092b513f36ddf3a0a7273e775825b907aef05a05aa9786574e88586995221fd5c18c0571ee91520c68a53bb1f3f40a7db07aea182f4e402e09fe97becfc4c3e0f51e94f8587d24671dc9a37b0e89e334bceaf1b7fe4af2465eac398c8e3a548cb0ff7247532537c539714830471f85038cea84acd43d2637884f944f8ffd4a33c6dc2b55e645b05d7c1e7b931fa82a208bb014de751ac1ddf98bbab7877c1b73158fe7dbed56f8e5cd45f79acecb5fc0fc61f047c363aa949e91dde6e440a231f9889185007fb2eb82743292314292d23e94f5198292e4346b94cd44372e1f480
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148100);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1403");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu98441");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-cswsh-FKk9AzT5");
  script_xref(name:"IAVA", value:"2021-A-0141-S");

  script_name(english:"Cisco IOS XE Software Web UI Cross Site WebSocket Hijacking (cisco-sa-iosxe-cswsh-FKk9AzT5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cswsh-FKk9AzT5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c745a377");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu98441");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu98441");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(345);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  '3.15.1xbS',
  '3.15.2xbS',
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
  '17.3.2',
  '17.3.2a'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu98441',
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
