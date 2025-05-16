#TRUSTED 4892fbebb80209d1cdbbf04a807d7fc3421b8c83703ea4ed03508e0f258859d9386ef67d6bd5dbdbccca3ed4a34bf5db6a6b2d5eb0a6b866f1e1774396dd5fe0a0834b003a6098ad528f2b8a5d12379b55387ef9cd5c8d01a95e8af8f32aa1a19516623d67c161bf4620f2ec59b4879d57e0bf6caa5235aee1e744958028618fb2bccd8f0af85bf8fda9dacfea5a95433fbb28f1478cec6bae8d451519e05aac32175483c0b9fcaac5f408096fecdaffa85d6a5a78231527927e1b1893f774812a2c795f8c95c8176d06512e573e70492d25ab516b6a6dd112144f2d031cd878a01349332d8e710e095d5261bf199cfa8a9b14e64245ac3b646e411ba906b40a6534ec0c60cb405ac63e8b24a60cd0587b6a2b3abe2ec5b8dfe84d5bce8ce1ab3963c5a2a8ef9aed4ab1cfe861d9d9f67e4de227af691dc698d4d8cd76c816403a205aebfe5708980e00cdd65fe7ae4055866716f2009f1559f0ccd42daa62d985ddef1d143c9fde2f85f748aee618b7d02a45e43b1b607e7fe97ddb49e557e6caba9750ce9b4bb56e08f0402db754496e15cbb627e73be0895ed57a7c01f91dcbf1832c08c678dda91a221126b5ce7be6ff3178311100681e6137011a419372dda42e8f1df8d8001a8bd94c20d14abe27211e503c1c8a1f136a64e0537402587c74567e35fa782f280b6cc9620332d5d8656e63585369b48f860150074af3d7
#TRUST-RSA-SHA256 0bcfd7ff7702668059588a5b54b1b4a8ab3a1293dc5eda4e5a6b7c3eef7c916e5386120b0f4a3117578dd294dc75d0ee87cd6133e875ef76a3b53c86864d76e528d9aa7eeb826ad959543a5c2ef8ec93bd100a2b8690e207b558cc34bc07e6c936fa9f08e142d11df791827377a73aa36f2474602726c333054107115afbb1079161dda326709c0d01fe13359e3ce6c08bb364e881ef417b55a05bec326a5780151cb7672d8881186b679aaee18db0a4138a584497555762676f45df2d97d1b8e450de055784dddcdf104f43e760282a8fa7eb9e27e1f1947fd84cd5e90c34cca9081d35e3c0b68cb4c4a4bd9e3daaea407eaf54f1bce967ee38aa054b3281d22aee547e8ab52b5a70cf8a9d576ee286ba9ab13da71edb8fae6ed41688da76161db7571dc7c9961c42f6a189031d275f2f6b6a25c8b6a35bfb92952587307a2dbeb78747b7aab4fb8be6412ab00d85442871b08953372346e10207c41bf40d5e6622c71d56e147c1b148d65d92e18307a862a3aa16e98eee0f3ec0c5e99c9f0af3582643b13f8c4cc89dbc9a32b33331ac7989c0cf53804acb45eaf271ae50068d6a638b47f711123b775c17a4f93afcd477b8d37298968b44e18aef31e33f7036438b16778913a677f732d0d4ab77909357023f4b733bf55cf6d50e2db160be0ba6f119cf5c16cd82c27af384d35917703246b802cf2db02afc34e9b4f1190d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154343);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2021-34736");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy91321");
  script_xref(name:"CISCO-SA", value:"cisco-sa-imc-gui-dos-TZjrFyZh");
  script_xref(name:"IAVA", value:"2021-A-0492-S");

  script_name(english:"Cisco Integrated Management Controller GUI DoS (cisco-sa-imc-gui-dos-TZjrFyZh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Integrated Management Controller is affected by a denial of service 
(DoS) vulnerability in its web-based management interface due to insufficient validation of user-supplied input. An 
unauthenticated, remote attacker can exploit this issue, by sending crafted HTTP requests to an affected device, to 
cause the application to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-imc-gui-dos-TZjrFyZh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f90719c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy91321");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy91321");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:integrated_management_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

if (empty_or_null(product_info.model) || product_info.model !~ "^UCS [CS]")
  audit(AUDIT_HOST_NOT, 'an affected series');

var vuln_ranges = [];
if (product_info.model =~ "^UCS C")
{
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(2g)'},
    {'min_ver': '4.2', 'fix_ver': '4.2(1b)'} 
  ];
}
else # UCS S
{
  vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(3e)'},
  ];
}

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy91321',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);