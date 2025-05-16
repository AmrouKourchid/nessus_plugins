#TRUSTED 19d3976ed773a6d350699c48623e703cc1515ea8a39d4f626a77307a43e15023a6da490711e5827901ad75e88fd453f4cb3f6bdbf26c2df53eb7a3b5e67360e981105f8510f3f74a92411eb1408e84c37fd7d4779fe7f13ae43371c70ba96b5594875937445ade3a870cdafaf4bb716d1534d56c695437cf831cbb9610fc5ef2c01547e60a4fb15883fa7ad470abbbf48d20808f1c18d0ab97bd92e18216de5d1aba5ce779eb91edf6d8f1ef10319d313f0a9ba28112bf39696ea14c8096cd59e845e918a6e7febc1367521b48afb5924f3d5a4f172139546c28ce98eebfbf575d7ea8d3e159871b4d7b695a040a095f51602e2a399455b562f31f95c2d9a5b506f7d2e7c8a95a86f23053f37649a071d2ed7432dfbeb806ceb2fb77028bf2e02bbb6edd8724bd98e25d6ce442612c5fb24ceee34be80f55e92a43dedcd756b61f642a9910c127027322666be5c40914f92d650963aeaaa64294df3a1f8fd506d9f82dd24b29bfda6dc3732482df86add8e8c58d8143e23147e51452ab13990e1d87e388fdedf356fbd12a826bdff3f70fb95a3cfe9f87749be3859a21d798adbe0505cffec6ddbbfa0037f73221b0cc3cdb031258267f0d90556f9baef8e27dff159fcd4cb6394aa9bfc9c2efd0aaf8ebe2f405a4042cbf5592632a0b3af5608281337bbfe7d1c6e111aff97d90046fc42e2c4fa6601558e57a3ffc969e5409
#TRUST-RSA-SHA256 829ee53fd2a1a5762ac021f6e08bb9eb690293472dd2587721905a0743c25631acaddedddb7b0fbb02811c21e3b535f2c36ddee9970f16d2f73def40a3d5371bac4a4e4e139acdeb1c84f691491486d8ae251b05101d4c6c70cff675c59d16bc543f9cca7cf893833635d538ea0df9fa51178c4f802c9f93c1e857f256db20b23ad00529ad21d8d4141d622d4a3b1746178ad58b4662a0a80a2b1c0259af1ece777e3b6a60b0b611635a98d87f3f488adb7f952b41177175e67936777de2dcb8645ec3e4a799e2b88a17d1acac2f4c2f25b038c7bc7f94ea74dbdc320f1b106779e188699cbc59ce890184ca3eb91ca15520f15538acccebbecdc665fb6b1d458a24d176bda824c776d73437d926484a37026d48fdc5728f34ec5d9683089ff63f33e51437844137378033eb6f6ef8e515435031c03199df33b1ccbc11258adf1c65f746d0751250182bae6164da1d5212b40e88a5edce8918265cfee0df891a6880802d541cbc94cdb9ecee1a061918535f17b7a932c31185530a43275e87021b5c088d94e3e25d7125bad3b829f67bdc209ac4c665379a1a2b7d907bf947d13ea6dd207925600522d1cd623557b890f3abb8302fe28849ce76e8b13ec4a12204715f9e693f8fce7444a63e6e0efceae93eaf0b81fe10fd9cdad346e9dd0652d3d7bdabe43ca7fcf27b60693d75085184d7d40c2b96a122f0ccc2d6d7713cea
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137902);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3217");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh10810");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr80243");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs42176");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs81070");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC");
  script_xref(name:"IAVA", value:"2020-A-0260");

  script_name(english:"IOS XE Software One Platform Kit Remote Code Execution Vulnerability (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE is affected by a remote code execution vulnerability.
Therefore there exists in Cisco One Platform Kit due to a vulnerability in the Topology Discovery Service.
An unauthenticated, adjacent attacker can exploit this to bypass authentication and execute arbitrary 
commands with root privileges. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38e0a857");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh10810");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr80243");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs42176");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs81070");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176,
CSCvs81070");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.9E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
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
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
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
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.0E',
  '3.10.3E',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7a',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.12.1y',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['onep_status'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh10810, CSCvr80243, CSCvs42159, CSCvs42176, CSCvs81070'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_versions:version_list
);
