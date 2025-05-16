#TRUSTED 98826907b74aca5623566964d139104b41803dfcd8a78d5f19a92be708a115fbd9c4f691f1834ea674b1479ec72dc4797d3ab7fc75399e049deb5f33a31ceea8a222279d9dddb0984c9217f6349428ed99fb59ac869fea588095842b3b95b2c2951dbb0e2f294d635b3d779961fa1ebc7c1010fd87474dbc12a71690ea08b0267020bf01457c8eb7c66db2fb7663892d960b493ac4bb73ad2e33bdfb2a7d902803e675472d015ea604cb4e34b767d2f6dec9b3f218ae05c7cf2ad8a5973f7a78eaf8fcff5ff7c900e1ade856d8b1a634eaf70b7afa95a07ecc9fe3ea2373f84345a88b43a9f07d4325c7e5e75b63d3f3d60d72cf99b10700cb0d0381676bffbd7c32f8a595378ac7d53648155db31ab3815e23326198c5d95b854d8a24b9da197a7ac83be03dd6573b9d0cc1544ed2a510ab94abea84b6f2b3a83a52295f71b440edfcbc5ede08b5e4fcd774020adb156f0b069921f78a835a556dc7c9b2ba58529659f6ac1ade5e58cbfddebce639377550e814cd81cf778073f43a9ec38169c934fea61550d8aff505350a4373264369b9d8752cc76ac72cfbf824c7c8e9565358211715c594f83738fb114b2a234559fa8a6018b0557ee212465ea3dc6b595b5ef713a2d7c5ea83e4c880a6eeb0ed7274b07a72924448dd73b4e4022984f3ce6f790d9fa63099a4652e1d15ed4b04a290aad77df86caeead585d9b2a25e30
#TRUST-RSA-SHA256 2080a17c3a5a6a0a58a4f68d032550af45a76d4a500fc2db96a4acf78550407c9e0ed747e30aed0cc1096f5888e666b229d8940cc3db221cdb8128494f446f675a402efd252956276407d53d77bc8dc701cc30f4f7d728797dbfc6ec957c8bfb904b8fb29f02e1368220602edf47bdb624ff96066c7b8e59f25a62d584823212df0329195dedd92ee462167f8c80c3e7cc709e189c1a8471284cb273c67d70bb32a382d929eea25365f3f6f00cfa796b5495b4f613aa867d97c24abf16eef8784a2ab7311779e1a52f2a213db3aa5add44d12b12c0079ac6b5456631ab3f15db0146804e1ee1331df257a17278aa49b2b24d48481873ad7b795b1f47a6a206472d921be8be1cf8fa904f4929de1d8843b8fa33de5b8c0ca6065f774aec7bc11cce5b72a2b77af426cd589b833f565bcc594ba3f89541aefcd56d0e113f0f715622a98c3241b8c0c3f544b1a84544b216fa12c3e57dbd483dc248630aec9597d9713adb8352aa2f8a02190710deb1839b1d31748f780c66d0f0f7bd268a4d37c872d07249ebf394c24bd28ee736eb0a4a3480093989fb3ea40d7f58c765e165a32a9b74f0f3c34ffab286832271210b811784c26515a6d908484ec3f4c2941b16859d0a5908bdbda92683bfd86f4af7dca72b2a82658d2185cf38b343fc90e90decb4a4bb186b671999ee5996a755626f01d03ffe39bfbec6acca024bc6e7d182
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138094);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3203");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq92421");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ewlc-dos-TkuPVmZN");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Catalyst 9800 Series Wireless Controllers DoS (cisco-sa-iosxe-ewlc-dos-TkuPVmZN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-iosxe-ewlc-dos-TkuPVmZN)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ewlc-dos-TkuPVmZN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27cffb9e");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq92421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq92421");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

if (device_model !~ 'cat' || (model !~ '98[0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
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
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.2',
  '16.12.2a',
  '16.12.4',
  '16.12.8'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['trustpoint_lsc'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq92421',
  'cmds'     , make_list('show wireless management trustpoint')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
