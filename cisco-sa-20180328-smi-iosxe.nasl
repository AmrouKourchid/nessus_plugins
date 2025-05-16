#TRUSTED 56c2cd1824c5952060e79457d2e935dd740f9225710982b99d4676a819573209aeb5f3fa90d9c090c97142d38549b0c95e0f78e23cf023b3618a6b4fad7f42d6f5cba2ebbb6b97bd5f077dc3669857b5788606fde41405688b6ee48c2b38cba1d2d5810d237e903a2de67e6ad4e02028e93a7daad96b6a5fd05e94089b518294c8f00278a0d5a430a90933d3657d177bcf8e5c29697b7b1fa61cba3128503ef1594872cebe5ce0148f6a0537f694ffaba2c11031d2b3213f86bce8602d361770508fac0d2311517b298018eb9587ef51c278a5f8254a2017c2a9552c2f3bec5759f24a032b8c917822734865567cbcb94d8a94e79c21e00001ea35bea6a8ec9ddb18550bd595fcb70ae267219a7df0146ee39e01a823d295e94e2d0d1f7018b76ef02cde2a30e1a6078498783003f41372ea81ca0c4fe33d12419a66a66ad2c12e02779602e05c96e2c1983f2d4a0cf006978263bd70f52c5b561ac05c9557491acee8baf7f8ccaf81bf35a2458ccb6399d777e63e926a2f8b7bf111c1bf9cd42ce14df70dad0a4537f75f75f192975c58e28e56b0df9fd4d87afe8c56117d434312f4183d565143be39094eef91d0e23434d2a7fb24b3ee4177c294f012c6661fb9306d5759b911ff4e8244b17ae98b3ed6100faacada863f995a557e8a863f3c849cf363a0b6596fdcfdbd49732694fcd52cf0e2fddf2110ff767b8f2d201c
#TRUST-RSA-SHA256 7e161169ff5918ff2b6b49a171710b3638fad571a3bf116d2539adfdabb1575a527d2c2972477eac199b55a04de9a8ab58df74ed29adf92f715661d69c1ecba1db07e3d604799e13cdc3f4408d412ff060a87eb7f8c83b2cde4dd8c8f388232bbf867ad17c966d6592fb67d3b903c280dd2ed0bb5f8894f50d40f45ae66bf036fe3f7f5a19609acc70a8f250ff0f4c21c83abeb85d3e21bca0250c822fbeb1bb777b44786ffb9775601af1379c71d97f3eca610549bb540b42ac954cdfa01dc31a5669b3d0e8eabc2de67973d445a1b99908f6b5521e8908db12b71c9171732c498964ac4af03ab01fd581f3404e99aa816069456c8fd3919c6ef0261a6270e9d9d3baf313146f09d4bb8ed3d7e91f3450e5c02f57b12c759dad7a48c820070a7dfa7124c665da69dbde01207d2c43b7b69e8ef48e19c9a61c617e4e80669ea8510dc94e9d463e9f551608c16a0e353a6d59c41184afac0764ced785f187ee5e7f44d9f7802b2b058e8f5581c3b4c690a9aa6b031b9e6a6ce6cbd73dba703ecdc99ea2baf4b06d926bc3e48ada8c03251b8ac9ca8ab5fd00e8814ded8eccdbe181bba6430daa2241773222f77958aefe5268bdb97068a520abc984d8bf5eb5044173f1c47758e424e15007678f072901ef42ebe3c6fcbecd6d0f50462b19d7379cead9ac5e8ab21167424474ea5c0822cfea149cbcefcd90d074c4346a4b9d93
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131323);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0156");
  script_bugtraq_id(103569);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd40673");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-smi");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Smart Install DoS (cisco-sa-20180328-smi)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
in the Smart Install feature due to improper validation of packet data. An unauthenticated, remote attacker can exploit
this by sending a crafted packet to an affected device on TCP port 4786 in order to cause the device to reload.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c08d6c6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd40673");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvd40673.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

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

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.2.0SE',
  '3.2.1SE',
  '3.2.2SE',
  '3.2.3SE',
  '3.3.0SE',
  '3.3.1SE',
  '3.3.2SE',
  '3.3.3SE',
  '3.3.4SE',
  '3.3.5SE',
  '3.3.0XO',
  '3.3.1XO',
  '3.3.2XO',
  '3.4.0SG',
  '3.4.2SG',
  '3.4.1SG',
  '3.4.3SG',
  '3.4.4SG',
  '3.4.5SG',
  '3.4.6SG',
  '3.4.7SG',
  '3.4.8SG',
  '3.5.0E',
  '3.5.1E',
  '3.5.2E',
  '3.5.3E',
  '3.6.0E',
  '3.6.1E',
  '3.6.0aE',
  '3.6.0bE',
  '3.6.2aE',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.6E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.7E',
  '3.6.7aE',
  '3.6.7bE',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '3.2.0JA',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.4.1',
  '16.5.1',
  '16.5.1a',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '16.6.1',
  '3.10.0E',
  '3.10.0cE'
);

workarounds = make_list(CISCO_WORKAROUNDS['smart_install_check']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd40673',
  'cmds'     , make_list('show vstack config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
);
