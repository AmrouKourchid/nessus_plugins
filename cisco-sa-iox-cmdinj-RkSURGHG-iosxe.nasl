#TRUSTED 446752068eb7607c4e4a8e49ff3001e95ed8ea6267e82946f9d0b6142575916ff51e0310f3a48bdb46ecb4fb223ed935c546c9ff02db5ab16770951ac0ac6b81c670a2a4eeab02e3f2da94a32ef2b452944fa5d5920158e13669af76f50603b2bcd972e56ad656cfafbbc0e0e0af1d9f6324be2cb74a44368a07c61751957ee21a1398dd4fa6ab141f78f28bf353d5b04d1580406b0a1a01046ee77d427b2946895b9fb0de45166b4a02b45e3a9abe92e21b059842b2ade8f374ff7561904ed7941211c7b0d0f933e467abc2d84e2234d0a8d5cbe0b6b3bbc9c9f97a9d48eb51e75dcb71a335be43de28eb319732ca47ad6740541203c4ea1fc69bc6e359890523c4193506aa8175024f229d08a3909c3c9c28eef06f21c0dba370f10113d403dd6822b2363865bdb3c7d63dd3372cbcd319586502ab1e976d180e6d44ad6e610f44901c87cc7456c1ec634121874fe6fe6392e0b08ee982603751d28e6a6544b8be147be2b1757dee266b89f552d0b216769931715a0c982fb7d2c2c30aeb094d6527e200e90e75509b53e9fb803105ed1612733aa68f813fe940956e40c8cafce9d6e4bf53c9ef805d85caa275ffe20ff7ed3d57b422b7ed39f58739662d0ed7bed3f3efb2a1e12bfa150894d1ba72c4322b81126db664c554e7a22e9330574fa133c7e5095d04ebcaf3ce3faa4737161c6aecfcbfd3d1a035775b7c3f01cb
#TRUST-RSA-SHA256 049975c5a1d5e4a749e5b9b1b6c263c4c501a692efba8fe6cf943978e2bfb6fdc8d0e2a42e9913995b75404addfdc297de993fa4b029187b726968fe93872cdc300c33819bc53167cf25fd9264082575c7e681371dd857466c1df8553961fdd0bf4ae958a70aec79951711e4b87b757b4554b4d37df264a41d018a05f4771c479410bdb5eb4adaa3cce09419e85e5de5114d98d4845289e6cd68e088e09199021d317dc609a43e19c7e4b3a71d2a675e36b4ba9124d883e508443ae584f658b07dc35feb422c626ddb3b132f3485480e95774716b66d3252fe2dcca1f435233e0181f7185a6b90103600d898e98b0f506a5d9383c9b2643fca0bfc1b7873b180bb6c00d62291dbeafd1a35edb4a75c5c638e70a5c9037c73a3b1c8358e2a75559bcfa0beb4f21cc0c1245911e660b0646621ab2cecd11ef7e75b6c2690f497184ba35cc973cf1aad94f11e7eadb9691f8444f5a775e672c3b23b39fa2e0e85b8537b52cb423ca609da72961a025d282c121ed05c66f9daa8e8fdb2d21d05c5b28ca28e3c3a98d752ece06cb4850d29369504a0a0f256a2db1215437939a77a2a341d0aaa142418237c49c1d24493986ef137dec7d71fda7af852bd8d966d5f8d680ed91c9dd9fcaae22c9489f9e53fd9498f88e6d8d11a98a5c4b018151e9a7ef7c20dc864d20d32d1904aed41099d8f255f7b519061927cb4c4b126fd23e101
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148095);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1384");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw64798");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iox-cmdinj-RkSURGHG");
  script_xref(name:"IAVA", value:"2021-A-0298-S");

  script_name(english:"Cisco IOS XE Software IOx for Command Injection (cisco-sa-iox-cmdinj-RkSURGHG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-cmdinj-RkSURGHG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e004a29b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw64798");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw64798");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1384");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/24");

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
  '17.2.3',
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

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['iox_enabled'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvw64798',
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
