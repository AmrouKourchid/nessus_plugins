#TRUSTED 478b64ced7c3b1cc1bd3bf65c289e7148b48b24ce0b06d6bad64d6ccb8abd73f859fca07b7fa15a279292fcab095036ecba7a9861b25ce6723020902ec49a7c520f0bcbcd7e725fd3ae2b5a2ccbad397be7d1ae3159ae2deb981ef3026890a1ad0ee741b51c7a1798eab3435f9538a67d93fd1d98380f834019c3d4c43d16e91e3aaa1e8091c891c6a960e0f425cf26a6a5c1158bfaa9df0747a46f4fef7484343de764e6dc9fae15f915a8fafddc590e4a2c7e8bf5288e7c0ae4e57e4b2d8d11bad25053edb322d73c62a4b099850cf445ed38052805695e5b8c8cca9c7bc73b33586c2ddc9909c7416c52740c666feacdca37ea8c4005dcff45064497fc4be829007b2d93eaf156956a44f3623a08b3b080d310d500badc53d2182b29433b8aa5e28128ba93930078cf40cf38c6e8ff6ed42828a6eb024ebcde34951ae5a34084a91889afee7f14f19f5c07b955864463e71a0487949a56da4316243a1804fffe882bb12b75d67771be1114d07238341d77fdb1b4e717e4408d7428dca2f3dbc2fe1743bb144eb755ae74dfb91de4e5e856c375e0c901f2b9d7477dc74881808607ab7216824c2823132a1abb2bdc86a1f5321e596b9eb16e225a00b9d895b1d199575ffcb70dd37efb7123a25e7361c3ff9bf30824c54c6b945557996e9d4d46f722280462079c2dac78b4f6696807cc02093c0d6d91da4450de7138106b3
#TRUST-RSA-SHA256 9300db63caa69e437a9f471c7b6a91c452dd59c52065d61a1d8ccf185e72961dc75e89e7fc19c7608f108e222345bbf9596a1624950c70541b4369408124afbf5057edc3559d60c50dff1a8ec1116b7cd95ecec085874030e5610636f8cd83f6cf174e5fa80bb0c9487e062b3b075cfa8c714a9a8498a2db5345a1fe316c82c23d4cf3f7dc4e546806c63b8dcdf1981dc4609bf311efaed549d1644f10c6a6621c0a220bc809fd80b3566f57ceb6470ee2433e23695ac636fe0375f18994bf9077ed0a0fa4f0cff7316f2c3251020b2a660fdfd33d5fb1b885949a12821bd98b299bedd550431e7418458ffd3d6d4a79c59e919dc243a594c7168cb9933389dda5633fb562b961b532cb53c0632e65efc7c70e2cbd08d431822b781a14e7c5f1f6a7abce47bd9704ab97093aaba11237b7893fb1b4f666d45ea8a62cf2821c935a138c210f698d66fcd7aa71b4c152f65c8c09402386162183ab4720bbe081b12533bb32c3169972b34fc21e7aa2fd1e131ecfa0bef7a7e76e2971ed6b9a0aee12bfe353a80160731763aa2f2781471dfc1bf4961011a1de3dcb03bf1ed68488c7bb47dc21cd3cfe5bd7c6708e34cfa793ccfa9da065003a3e3472ef0de6e2251b89598d4ac6d9d3e166fb0577f74f1b8ce024ea4fd644afb34853729a55119fbb171a08b1c53b26ab718c9ab8fdcff445abb6a54248e5230efa5822875ca049
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153208);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/07");

  script_cve_id("CVE-2021-34718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx48017");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxr-scp-inject-QwZOCv2");
  script_xref(name:"IAVA", value:"2021-A-0407-S");

  script_name(english:"Cisco IOS XR Software Arbitrary File Read and Write (cisco-sa-iosxr-scp-inject-QwZOCv2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by an arbitrary file read and write vulnerability 
in its SSH server process due to insufficient input validation of user supplied input. An authenticated, remote 
attacker can exploit this, by specifying specific SCP parameters when authenticating to a device, to read or write arbitrary files.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-inject-QwZOCv2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c358fbe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx48017");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx48017");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Host/Cisco/IOS-XR/Model");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var model = toupper(product_info.model);
var smus = {};

if ('ASR9K' >< model)
{
  smus['6.2.3'] = 'CSCvx48017';
  smus['6.5.3'] = 'CSCvx48017';
  smus['6.7.3'] = ['CSCvx48017', 'asr9k-px-6.7.3.sp2'];
}

if ('IOSXRWBD' >< model)
{
  smus['6.6.3'] = 'CSCvx48017';
  smus['6.6.12'] = 'CSCvx48017';
  smus['7.2.1'] = 'CSCvx48017';
  smus['7.2.2'] = 'CSCvx48017';
}

if ('NCS5500' >< model)
{
  smus['6.6.3'] = 'CSCvx48017';
  smus['6.6.25'] = 'CSCvx48017';
  smus['7.1.2'] = 'CSCvx48017';
}

if ('CRS-PX' >< model)
  smus['6.7.4'] = 'CSCvx48017';

if ('XRV9K' >< model)
  smus['7.1.2'] = 'CSCvx48017';

if ('NCS560' >< model)
  smus['7.1.2'] = 'CSCvx48017';

var vuln_ranges = [
 {'min_ver': '0.0', 'fix_ver': '6.8.1'},
 {'min_ver': '7.0', 'fix_ver': '7.3.2'},
 {'min_ver': '7.4', 'fix_ver': '7.4.1'}
];

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvx48017',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  smus:smus,
  vuln_ranges:vuln_ranges
);
