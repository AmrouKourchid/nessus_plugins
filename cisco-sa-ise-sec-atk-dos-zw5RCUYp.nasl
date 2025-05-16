#TRUSTED acf89756ba2042dec083d6c3220247608ce8131e02dccc92758581bdccea232798ed0779d0024cf09ba68d0cf223fd94e436a89ae4a6bcdb51b29c7dafaa368904c104b6f606027a5b9b8dba4660166d8b2f4e8ca5c4c516fe2a835d923e67c5111eb3dd440897c1167e0a23abb0be756a717ef4496bbf9743b5f6a33ecbc0afab94deddb6e156f3dfab2f2c297f8c4cc46bdebb09dfb094a2ddd4e5881a4d407f40e8d01f912e9edbfe060e9ac141189f41773afbed523a2c243bd49b63a94cec671947e6d68f724658fdac6f85e1890132c34df4301ffbfb375434f0a6c0293c69eb1d4d894d1cea14d088f635ca9d533f205122bec9a6ed67bfa172a956c5a0eb1ccf50363dd1d2357e7162dd9256b1713d8075b50a559a5ca15a319eb3f2b5b78a6f3e6da3756b264c4fe519c1151049dc16b9a618577217a61c43793537b151fa6335fc35d9318ba3d067565a083b081cf4ce7f4b94b27701f3644a0ceccd3b21c8090ae6bb88020087e371a528e8d8df47a1346a3731bba79f861649a85b9dbd8b7133089c4b3897bce56e63baedbadf74a4cca62406dbf794167e72311470d879f0e6e2122684ae739c95337e3800b4a05b4d5eedb2f372b687df8e7febea04b82519afd317e0e019db5b39fb09d7f663ae5aae07877670a89b2c9e3938926d34e9de0291d0beb5509b1eb3f0dbcfd47676de2906af2be4c2702731b0
#TRUST-RSA-SHA256 30a258595b516fe9ebaa3303d1200aafda23df62de98b0187b3d82237879c2601e0bac5006f919f5a96b59ab2733543951cea32030b0c8ee802a23b0da79fb4d00a4db088fb8e8ebcab3f132837243c9679f1b6ae7e300124a0f0635d91004a9b23590ccf9fc1fd2a19880f4a0b73be5e57bb01c2d30bdeea1a5e3edc38fe80aa3c595046146e0eb4f427602125e9f0ce2e86df33c007877d65450ee74a4473e9de71acfe771afc449924558e3870a9d33800f340a85dde9d163f1892ebd2b4ca3fb3aa9e03fdbdbe0553f4753b166ac6e2c548d43bebd432771215daa0ce96cc51e36a3d8d08224ef0c3235474820cbbc9735b3d8bbdd115445dc19a5e23d0ced4a55e7ff110375d318066971f62264864a1b79cc2a4af9cecb8bc168700421070b52c384e5c67bed63a77561424522cb5debac786bf13d2bef6702f00a1b2fff4ccc6823fc0e4e6602e6e2bf2f1a878eaa0160b4b8ac6c46f745973ea53e7a49cbddbdf364f6bd82f98f98b830f6974de266140eb4ef6b70a50d3f48289e73c98b5a43a2fbe5244ac23aad8de87d77bae2d67f7edaee6112a10d8d26c62684262ddb8146d6f50b02b73a909f59073ebafa2a7bb3a9c0f0f62af703ff3647db69afc50af7300d5dbf255b2cdb2b1314c24e9cb24753cd52d588ed2b74b861d91428c0ec82df0b4cd7249d30bc64c89f6d440242dcc551ff600ea5cf6621b526
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166916);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/25");

  script_cve_id("CVE-2022-20937");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz99311");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-sec-atk-dos-zw5RCUYp");
  script_xref(name:"IAVA", value:"2022-A-0462-S");

  script_name(english:"Cisco Identity Services Engine Software Resource Exhaustion (cisco-sa-ise-sec-atk-dos-zw5RCUYp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a resource exhaustion
vulnerability due to insufficient management of system resources. An unauthenticated, remote attacker can exploit this
to delay RADIUS authentications.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-sec-atk-dos-zw5RCUYp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f92365b2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz99311");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz99311");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(410);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# Not checking for GUI workaround
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.7.0.356', required_patch:'8'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'6'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'4'}
];


var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz99311',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

