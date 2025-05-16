#TRUSTED 5590fbef748ab51a6520bd21c99decf31221515bf4778b868c530b37204b2d58eacabf8c6946ca461442c8432e6ba2a7427f81515c05448d88cfbb890fa9745142869a3bf86dabb4c11ee9225632b645e139abdc518283838d2e6bd6fe210a78777c96140fe43c4b24c0af954b37c79c526c77d85109691206d616465d75ee06d3dc81d2900e6d62507948aff429365ef4e026af09a5470932042ecc0e9d25d843d582e7bf2aff470f809599d1327fa72c343943d00713c85c39a7c96bccb320a073383899b2032826095c313fcffbf76383f4a8fdb98f72476778bbe09122b5e76a9eb2f319a9dc3304f3b97de770485f44720175cdcd85b772dbab00f8145f06b9fb0491390ba6c6425b19b9ca3aaca36d7c233295fcdf191bd6c2d12ad8dd9b726276b27bb550190b5a1e3122c2f807d1f509ed485a0fcbb12d314db5931f728db999ea76440db8873a254627f58ed78d534c04e60e9694d23ea1c072a2d4ad24cd8e9df2f645523bb5abc063e4d4820228d2d3e18f34240fa5ee87324f6cfd09a5fc836fed67a6408fc9383853d2aa6026e0202cf3885159b6773f9177a52fad505942c09fb2e0724439521c4e9bd454e4b9f9e4c8ce9c997c0bd20a4e23a79130adeda738b75326e1d4f1815009ee1530830a1f063e9e8055e134cfdbdcf196454a831f442146a9d66387470d20cb861e16f5045913d9a7c15054de39e8
#TRUST-RSA-SHA256 67ba9bae4dd3fde626ee20203db9504061820fb3503f7b3aa0ef2c32e81294542fe32c46fd604e7b491e45b3c399ebd82bf631eb43c2294c111f4f06532bb3b5fb587db45e7afade380c11f37cde606ca8fe418c01965ee351a4665faa7d31325df6f4ed3c6f26095b478dd567802ff3d6f3986f37a3a044f131f65ea1c604466c705f344af11ecca8364b720ac5ae09b646cc1e6d7d667e6cf540bc8a6db4a919de405ff6e3545de3cd4fc1e580c4987a4e5c366960d188b4066a03a7f1ebd0f26f81b5b52940049713facd326adaffcdab39df549e97038f105b2962f08d52fa78b7262a9d3b9ae35e7aee946247f276d42dc8cdc8729a461086b51729e29ce581ae78297c84ac7e328785c70d9178e169b948042edd567d00e2becf922a7a68feb9e9b5eb21029d9044658e217b20876050b16b74fd5420c4e517ed07ef1f7734da4a414e5533d7f21e1ff1c4ba3c9c6c7c66ebe984348298dd7872fc8ec83f7fdb932059219753cc4c17352bb02f834eac069adc90355ee98e4f4a69b07db925f8f80375cb6bb25bed7005fff2e130eebabe263de6d6c9691647af2631188e720b08cc33a8cc78a3af4b1a9a6be8695e71b52c0f429980a626b34a637cedd4411c96524c10577a1091a505470a785dbb914a4b60d9207fffde2e51ab39584f943c94cf380fcd941d843cc30be02ab28232a87a629abf0bdfc6965508e3c4
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134562);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2019-12649");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj87117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk12460");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-digsig-bypass");

  script_name(english:"Cisco IOS XE Software Digital Signature Verification Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability that could result in the
loading of unsigned firmware on boot. An authenticated attacker could exploit this flaw to load malicious firmware
onto the device. (cisco-sa-20190925-iosxe-digsig-bypass)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-digsig-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb9bf05a");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-72547");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj87117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk12460");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj87117, CSCvk12460");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(347);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/local_checks_enabled");

  exit(0);
}
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
model = product_info['model'];

if( 'catalyst' >!< tolower(model) || (model !~ '3850' && model !~ '9300')) audit(AUDIT_HOST_NOT, "affected");


version_list=make_list(
  '3.2.11aSG',
  '3.2.0JA',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1'
);
workarounds = make_list(CISCO_WORKAROUNDS['no workarounds']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvj87117, CSCvk12460'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
