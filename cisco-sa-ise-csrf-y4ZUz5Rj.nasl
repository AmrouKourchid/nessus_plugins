#TRUSTED b2f0af5df67317cf75f8a8370aa10788e5166ec1c546bd718b5c378909e57d4206bc0f212909bfe880965d692b2e99ad5490dcf96ece3ffd4006ab2bebd3629d0e3fec60438fe7830337e11165c2452e9de4601b07b70c69dfa01e3dc0f9748bee118adfd8c3a044709ae0ac8d8c66f6eaeefbba9f65f536387c0906cd570f9070648fb0e7ec7baf01f77994bf4ab03a45bb22e1bf5388cdddebf332e3b9d568e8ebf11155d278a9d98cfe0f6324b190a030b5638d0bd8e51c1b2babb8a83e34ad281eebbd8efffa5a92621b003d65437b7c11a1a6d0a21f68d8d941829b4121acf0dba7008ae4207f26cf1e4b8d18378fc8f0bdd5f19e9cce1a9761488727f08fbaee2daf51301aee8c46c5ebea7dde449ab303e4734d674d849295cbd16c9b0daf28a6e564e1f1dcaf5589adb35a9c0ee784b3db8721e9c0d6e2682ff87746b4698c7e767adcd8fc0bf472ca17ad002a8b78d167e4a363d274111a761cfb05045e2fab5bfb30f876684cc04fa0597f87bab55ebb0932e9db45f00fcc057de78900a052356f9e3c1478cf6a4046bf2601d0411a39ad587151a91b4256545603e71d1ea00ffb2bc7bbd9f9088da8e679fc3d723a81350ae68f4ca8647f946e384c283c5cc0957584326c14b3e5b4fd1b838786ecc1740e648478bb74015e21c3df80c13c5a06be2880f7f097116ee12ea976a197af1d0c46e1de06f3c9832dca
#TRUST-RSA-SHA256 5cdba017454ac40224cd719380d72253c36f09e3a3abedebc05b2cd058bc6e51c139afb5b14a16edca485fc89b6ff3cfe66c9a36f169a4c18df8ee9db11c09fb1a67fcee71e0a81e0fdea460419cb50271f959555c8375117cdc482fd9e305d91d653bf06c236da1e0d69700507bb12ca123cf9e3841a691b11f2af7e182eb43c2f23829ac2f52a81319edd4395387acdc3d612cb026d1511972feac7007c1cc57483fb8df9319fabd5b0826369e90eda58d6c54ea0bde67f5df053fae2b8cbd370132c32d2bbc6919594fa817fa0b0165113fd3ba2e316f97729b12cb56b36ef3d7be3621397b24df87191937f44eb3d1a0df24deb188c8c3b2e6018718023b88e0eab1ee4ac6a22ebb23c9ad279101faa362ca3fbc52ab80875b2edb0c317464cdbeaade71f76c4bcf1470f7457e7b64333599f56a7ab44b3beccbf8d2a14fa38831476db79840cb404c753697de1f05cc348afc56290e53fbae00239d7281afb228b5696b8f8a0cf38bea1708746fa58102077c71544aa6851feb74aa708bf9e2a2bbd0bf43d91803130c7c232b8495168d5f1c14187fc22e6cc38ff1914ea82d877528808dc55b986a6aaf05cffd9d9ce0785aa53bd74eafcd2c0143e3d6e71c739837b0a892bc936e403c2cc93bda11aeb7ee2163b35cb58c8ed4b034a026511a7e9d5888b81bac17597d6c85b46164bcf3e9a77002585fb6e846519d4e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206352);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2024-20486");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj33460");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-csrf-y4ZUz5Rj");
  script_xref(name:"IAVA", value:"2024-A-0414-S");

  script_name(english:"Cisco Identity Services Engine XSRF (cisco-sa-ise-csrf-y4ZUz5Rj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by a cross-site request forgery 
(XSRF) vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack and perform
    arbitrary actions on an affected device. This vulnerability is due to insufficient CSRF protections for
    the web-based management interface of an affected device. An attacker could exploit this vulnerability by
    persuading a user of the interface to follow a crafted link. A successful exploit could allow the attacker
    to perform arbitrary actions on the affected device with the privileges of the targeted user.
    (CVE-2024-20486)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-csrf-y4ZUz5Rj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74a0aeb3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj33460");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj33460");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20486");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

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
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'9'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'3'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'xsrf':TRUE},
  'bug_id'        , 'CSCwj33460',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
