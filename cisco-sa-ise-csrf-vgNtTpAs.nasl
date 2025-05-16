#TRUSTED 8b34de4162474f52d9fd42efb9dd5ea52d57e5278268e8064c39682ccadfcb41fde40a13e33a12b99a6b040de68f0e7be0884c9abe9e1e430c7f0f07345c61bdec57578c038f74612e4e69da307329ba8e6ecb354236226540ff185ef9738a726f52c27b33742abb72f5c9f761bcc0f40aeff4110769cc73c263523e49ceb783417d7d531cb6cb5a27203599b703fe39a3a290055f12fdd37264303ca51231b743394b15eaf62d3d07af899de49c63f434874bd670e54e57229f4d808be1313113c88101667e570abf63baf8d22855487715a1fd2ff3862601b3d3ff91ebb85e3db0c8388d5e65d4cd45fc771e9e12d3766cbbe9239d86dcaeb49e8bf76f205d72941a763221bc29322fa015daccd2e193e085b27f474ba5e6a47815fcc3c22ff0f31d070ab9e9fee215d022cc532f59a4fcccb9de7e7d3411635a5d7ee5f545136b7a490743dff7145a395d35af707688c468fb30a6dedd52b28f1dffbea60d929a32c7f23866143fcf351cb7315f65a91706b8f63f3bf60f484d06df0c7713932bbb969c39d781d45cf8891bcba9780d0503d9a336f809315ea1a97944d7a5d838dfaa7092d78b21fa05e6d7bcbd0b9d2d03adf5ce69bc63e03e69ad1dbb0f20b0d491ab0161c7fc85e849ad4377a7a12ed28379672cf89aca879456cfe2fc24db38ffc707157af14ce213d96a838d1ce34429e0f04db8a21e0dc09819f92c
#TRUST-RSA-SHA256 3e7d1d10a8140a61c6bf040234f52adb51bfaae65cc79668df2857076fab20a81f35de09587b172f5b69ad8c15fa990235347d0356a32372a7d09f73c96b2a66ce87a3f5a40700671200115c5a2f7ca3c92f8d41f984b0a495e9737bc3b898f313e1f02c39df5ea460d5b99ab2ea4e3d7a8c27d0724cd9e1908f24ab058fdaca72db0b2e0409c90f4a6d793235679f4aa6e1fe718ece2f7a01ff7d8b622acd281b1a2c96d834bf2cba7d7a1876c7610dddd01fd21417489778c1f59acd3a2924eddfc9006ea6d1061aa49b4e8893f99384c6f7a6d892674d16e629947f85713e0dc7e0917ddcf0488f905303be7268ef30cc4d8d4a292164b6e884c9a1d497001517ed4d57fd74e7a0079ec1220bb2c5da11ed38b7ad97b60f528823e3c6943963b4def8a4341314bfb4671941beea343fe6e16591c2afa037e8893209f121acea4992ffd749a0b2e9fc949f8e0e356fd1210c6201671013ebb28070970b0c0ca8c8d5b9c388548cd147ed053218ffe22957210bc1692787cd1bbcb31993f80949919fb70a922b14e873c8adfd637f80883b1f72526fa00e987d5bbcaaa3ce1a74f0a847ce240ee595ca809fd720519e6cbbf10fdcffc50236be530c01adde0bccf8b98bebf5ca825591b17158b01a3bd9501bd5a3917617126f6e944a92819d7f0ee54e9b19260380f61a17c346c414719228200aeb86d41f426c731a7d4cdb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166915);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/25");

  script_cve_id("CVE-2022-20961");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb75954");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-csrf-vgNtTpAs");
  script_xref(name:"IAVA", value:"2022-A-0462-S");

  script_name(english:"Cisco Identity Services Engine XSRF (cisco-sa-ise-csrf-vgNtTpAs)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a cross site request forgery
(XSRF) vulnerability due to insufficient XSRF protection. An unauthenticated, remote attacker can exploit this, 
by persuading a user to click a malicious link, in order to perform actions on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-csrf-vgNtTpAs
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86e31211");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwb75954");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwb75954");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

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
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'2.6.0.156', required_patch:'12'},
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356', required_patch:'8'},
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458', required_patch:'6'},
  {'min_ver':'3.1', 'fix_ver':'3.1.0.518', required_patch:'4'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwb75954',
  'disable_caveat', TRUE,
  'flags'         , {'xsrf':TRUE},
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

