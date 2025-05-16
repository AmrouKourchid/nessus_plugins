#TRUSTED 790dae0bcf43153ad7edb789292b47f9a1e991b86e5b52939b885faa02420e4c9a0db5b3d8bf098e237f8b95afb89ff5eb006ed4841d34e76be25abd1cd787ef057a4bbec83a05c69f8d88bca280e8f0e7b162ec6c7506dc1d3a32a06be35273a45a106e6c6c5235a4c0383316a689586b5d96effa550ef150873ef92f77882b96b78b29a88e6112ee00f417be76ce2986ba6b9174f3b3f3dc6159bf23d2e8356b68d995c6e41dc780d104a7841354dcbc789c2bf89eb38d71780044e6276fb18cc726f37b8444cdbb154e4a0ac5a9769f02ca750a0a0cf0288e95c8b0f5b1ced05ab0325b4e055141d26b1e79c7ca613341c1ce995d06f88667d51ea7320d6052283b21b82a63b0830df1366dd21f5a1217a64caa043947d79860b430af63850ae0fe59ba1f0c02d616168fff21d9fef2d52e01b471737b21b1d6e84219b1a04d404ca4ae30fc81d09eac22053f59180f7e30755dae152cab45a2455dc55f64532b656a7ba9a6339833fe5eb4fbc8756086ecd64a0ec19ebfd85602fadef61d4db1c7f550db821f8fdc4cdf2ee62b9f0ff359a8af6046a5d740f697ddbd6a966112da1c7e35ff4d9d3c5e42ce701c04831a4c9536ea1a91aa5c323d22bde57b81dcdd72de3e48045aa2437d58fc6866eda07ca4f7dbed56d383e29dd66b47f8ae9a5b01b9e25ba9d9552a5f20fe9dd57cc3e4e27605834fb4faa57f11293446
#TRUST-RSA-SHA256 4874ed5a03dffa675e0fbedc92468f730cc74f26d289dd0df2b515eb870ab544dc412d53b2a1cbffa20a0730d662a71a00298c21e35170f71a442930422999c698fc74190f5d6ce87896e3148abf13591cb55b2bbf6ee2990763a084a773b7450eb370fde4fdb0bf3aef6e0389fcd965a7296fa0c3594fe54ebbe1f4b7f23835836bf36add40a9acab1a30ba192ba90367b91645073ee8210f359e3f1da31d4ef0d5cbd4be0b3701ab29829c6d64c2a227dedba58499c479803043d4b92071e3d100acbc7750b60e7665d12fed5a80960742ab9408c599d1b407c023738f5e9a91880368827d34384a922aa741774f3197808c36c9e9ac8b7d7238c68df1d6363361459c498d1b04e0a37a4424d7117f541e0fd049b5f65eb0e5dd4458eaeef8039de8ad7a983276b5daac3211cb94d5154a450a4baa3b0027fef8133d34e25751043b00bcfffce42288fb8209744149532439c1e84e1afa4240807792a7afeb6c524c9af1b71b5cfa04c9648329fd98bcea7f6bf2049d8fa0d3fadc40ac6e42571ea421378b1f34c450d4c367c37dcdde82e6ee73d29a53977b8c7086e082ba84e16f5ffcd1187f5d067b33e60aa0633c6e3f840927026c6417bd7415a946a1ab53406c046413c7ea4eb9e01719078ca7fe062833e39922ac38f15bf19fcf64e4488ec7bd5ac00de13bebf99e3b22ef269b55f0faeb6aa6f463bf9cd82e8fae
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208142);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2024-20466");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe48929");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh78725");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-exp-vdF8Jbyk");
  script_xref(name:"IAVA", value:"2024-A-0414-S");

  script_name(english:"Cisco Identity Services Engine Sensitive Information Disclosure (cisco-sa-ise-info-exp-vdF8Jbyk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Sensitive Information Disclosure is affected by
an information disclosure vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an authenticated, remote attacker to obtain sensitive information from an affected device. This
    vulnerability is due to improper enforcement of administrative privilege levels for high-value sensitive
    data. An attacker with read-only Administrator privileges for the web-based management interface on an
    affected device could exploit this vulnerability by browsing to a page that contains sensitive data. A
    successful exploit could allow the attacker to collect sensitive information regarding the configuration
    of the system. (CVE-2024-20466)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-exp-vdF8Jbyk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7d56533");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe48929");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh78725");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe48929, CSCwh78725");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'10'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'5'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'2'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe48929, CSCwh78725',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
