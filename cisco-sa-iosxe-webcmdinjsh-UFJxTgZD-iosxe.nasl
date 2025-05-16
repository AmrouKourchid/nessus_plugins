#TRUSTED 9d4ff8e5b195107776785699f48b1eccc91572844ebcc0865137db0aa8df00c9b41310f7b17621026f7eaff1d55ed4fb9c265c27ef52a7b23ae5ffb8804ea4e48de9d5b6b8da24451adaf74fd0f8b30cbe8496f8098d2267178c02a6568e7ad22b286256fcd584a800b3844757cefd38c6dba5be6b6e0b3f8ab94da94a4df0a2ca7f4b98c05ff423bf6954b2c1b74adc539b857d4bcd15f5889bb889dd4aafface8779e177a816585fec2c7eb5d7e777ec29aebeb95da556cc34bcfc017cfb797e2a954084116da8632a30a94b9052a73d24f240cb117f4b23546ea8896d7d199288dc9c66b7bf3fb274ab345aa58f2a4263ebf1c471b4ca2f1e2e37db085637b588f9880b8dcdbc74e3eaa70d117c0d6da07e0d058a2d6855b401505a5ccfa6c12244045a797c362b6e8ca7effb75374019d9e0a3897b2d8f0f7c578d4a53e9b8a0df917f1e8e55648d5757a7b03fbcad3d089d8173a996295f8ece63bd1e5a6380e94a1317ef920e41f644d3a7a49ed25365fb7fd38d4ed6741b0a00b6eea3eedd840f1cfd9410ef09dc8b2b05c740e3f3713d351b652519d4bf665ec523ff096de4300d7f6fd268e2661966a6b63ff943c695ce6d8855df380e4d54189daa8ab71652a40962e13c5bbcabecc460d1c2a615022891f40a5efca4fb7e32bdcdff936006d1935586a0fc6b2a825ff886ac757e30af3997f8df3f2f7e17fbe0ba
#TRUST-RSA-SHA256 29739e11293dd340166f74b6b134396c34863490102c527d03b1785c0c6c0b0537ec9ffc10eb846246dbe16fa053f2fd8b200af0f064108b9cad055ae2b59be47f598877b8ad2449bbe94e10207a33395ea93884679112afe572c64d35eb53d0b2f0f7318a6516566fed1177dae520ff1758d2bafaa6ce4afb8226afc652d3efac30783734985be7251d2d0cc0c921109f3fcbc20f2ca4e8cc27486b48445f48f23557bd24225d18b402cc09aad0369933ad1a9f33157bbae51ffa7301c5aa1e7ecbaea88b255d8ae9bde083d045ab835d568b43e54beb445934da78c970200632eaa62e597f05b50195adcfaa24572630c36d01916f3e6e83953788cabda7944cf669dfab0f878ec199a9073179a9c6bb40c63c957ee8bff7cda27d4994b7a1f367aeed3fa049959f31abf27ef19e5a0b6b75e4817c7f3cb94fc516070c9eac4c8d4b9b7c4f40791329de8e33c558d05b6a8715318b77f94b0d40d0c7dac428a6eeac513a932b5a7da401e843dba3ecdf180f703c65ee20f245c4e9a992c67a084f7450baf316729516746d3b4b5fc436468beac8df4956d3f72d12b47a6200ae38bdf92d6e8f38f0e68c90541986f71424e89b897c365ff2af0fd633a4871f43fda159258e96997fe4ffc12c89b370bbf48cce4efb0fde948ac28dee2ed1ae9e14bf7f7f9f0e614049267e31a474a6303e2a12ec818ede49dacc953d782501
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148103);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/13");

  script_cve_id("CVE-2021-1435");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq32553");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-webcmdinjsh-UFJxTgZD");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/25");

  script_name(english:"Cisco IOS XE Software Web UI Command Injection (cisco-sa-iosxe-webcmdinjsh-UFJxTgZD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability. Please see the included
Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webcmdinjsh-UFJxTgZD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e57305e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq32553");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq32553");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1435");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

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
  '17.2.1v'
);

workarounds = make_list(
  CISCO_WORKAROUNDS['HTTP_Server_iosxe']
);

workaround_params = {'no_active_sessions' : 1};

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvq32553',
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
