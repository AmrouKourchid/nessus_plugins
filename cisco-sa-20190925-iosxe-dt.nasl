#TRUSTED 8cc8cea3584c7856d398c46623971a35fc8419b1885ddb3569f0d35d09fcc1fa86537d9c4737fd0280ff1c0b8275c28d7b0becca749138368738287a6384e9d3babe2c19e5162aae2b13a3a43b262093b6f923bcb3668720a9bcae738705b2b9e3545d27248ee462fd3a21d737bcb3618aaf3c3d399246229427d643f134879803a4971b05589f99f1f4c49550dd48eab7f9456b514bf6136cd560674ccb9121224468602bce6d377b7edc53383e88e6714889525f82ae06d703a4f709a9d26388a6498052b41c0d4ff599152cff4a56224a32c5e69ae61d312b43a9d9764067e7ded25b0f80a086f38a12c20f7f26fc04ae14dddd70f22b490450f34343d7101f2d8b6be1551c58d2fd4640497efe34c703bb4794ae5551e627e77fc6d92a4711eb04790e2dda1a824a4cde0c75a95d04cf40b2376338875d19c3f0d673049f65613c8016cdc8722e201f6e577c7ffacb8b8916730a176ca93ff14e00a949437c3fe4c8dddb2d0219bd5114a05910a3b3bf4765266415d2d37cd28986db5d5164251ef6daf745a967da820b5c735a108447418481f4e9d51bea64d409e44aaf8e0016b9c6fa44d05774ee4550709a8cbf37a74f03d4cab96ca9bccb3002e68564c0c292c909c3d183ac566d7778ecb875d725284c737e6bc650315f157c0af60ee9e72451b831355b1218cd792682fa6cdabca5f1f280bae980be288c7100e0
#TRUST-RSA-SHA256 3f8997e3211391ae36f7ee363bee8b73c3c75cfc9bb60a1fc6f9bfbdb5664b74aa08ff4b7aafa08c1ee3532032f0801ec4780b87e880d1e4cbbb1c8528943f3a4bc267150d352bc42bd9210b24d8d92819e66ffaa6394b2543a5f4313361a0ca684e623ecf3a6a5c371ae4bc4a88b68fcfb863945642318dbc052b3c1b16eabf7909306af573d8700ef4fee8ce807569df23373faae4a20994d4a6d4434083791eceaaff42f86235ff17aec233e4119d982b12cf4dfda8de9b410dde477841becf61a6716f47bde063ebec1d1d388326e8bf5add722084286f8223c7f11639451e15fc1f8573fbbab44f002583b39df553511c16a9e005f0048c0fc7fd7bedd97b60d695f2f19704f48394d7a95754a3e13d44b20262e9bfd9d416c22fca2d927772edd69a6ba0a09c0d5841b46e7f9bdf4ab1ab5892c36139117bf27617035d98ccf0a4d762c6e02e5ace73b1c4909fdc676bf589b92879f2cf7ff2e29f82b45b4baf9c58deccbed40a8c0704b7662fbc94195a25d00e43d603011705a814f8473e141fb924ea8d2993dc23a96d695ab2c4dfe0399ac7e0cd1809f8162dc70540ff8dad1b646afb7dc34f58e3ea8f99bfa93bec11e10e3a114b9f5e686f1dea2d0238fd7395dcb073bda3d540317944011a6c39c2c82704620452323cb68eb39ea380ef022d632175031b0ef1bb63a1dc32ee31857ea86684326b94949c41eb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129531);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12666");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm24705");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-dt");
  script_xref(name:"IAVA", value:"2019-A-0354-S");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Path Traversal Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Guest Shell. The
vulnerability could allow an authenticated, local attacker to perform directory traversal on the base Linux operating
system of Cisco IOS XE Software. The vulnerability is due to incomplete validation of certain commands. An attacker
could exploit this vulnerability by first accessing the Guest Shell and then entering specific commands. A successful
exploit could allow the attacker to execute arbitrary code on the base Linux operating system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-dt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86431af");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm24705");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvm24705");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12666");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
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
  '16.4.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['guestshell_iosxe'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm24705',
  'cmds'     , make_list('guestshell')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
