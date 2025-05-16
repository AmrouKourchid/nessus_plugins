#TRUSTED 3f3143200568f6b2ade033ccfae3cbdb212fb345f4c839360d529740479ad4be3ec7d5665f530fa591ee6f1df614516533c7db3867c00f1006aa9efe42db0eecb89ed82e6a8ec44cddbfc92f3ca5211efa019aa060cd8473e8dfcb0a24a81dc71041962edd44478b3d3dd331966b3e2531446f4b02109b4e488ca45bc7dee68080b8212b38b958a1c079c0daf1205f234582e2d313dabce51bd07e992c76b3e2b4ed017efb2ca9bfa4c7cb16af5bc6a519f1a0eda117ab4b35af4da9d75edb9e01b1642bea5ced36eeb3f7f32206ee56e52418a4d63cabe67b7e09139b052f2d67432385a35b349c32ae2ff2608a6bac191a921c2cc59482415aab1679367f22c3a025eaaf0cfb6ce7c9c04ebccfa7cd102ca4028625a70280fb91b7d67f9392c313191b7b4cf0849b3bd7366cf9fc1e37bf9b13b0c17da7023ae6adc6e37fcf57447ce44efb12da3cc27620ea2e719fe0d6c612f29b67a33d6a207654d50e3a65531d2f4025a454e8cacee418ef0c597e02409a1e874b1594d08a5c6a1b597e6f2651da66c299832054b66eb7b5e211d822975f807101252415d83b3992ac2912c420ba10da0952509315982f32fffbbd6317b4b980edf77853eb9365d077cb5a127782495828af9fbe2982b11d601876e248dc808fcf7b19a966a11801802537b3338598ed829eb146ce0fe098f16ddd7e100b02177dc084aaefb760024ef9
#TRUST-RSA-SHA256 8b0face6765bd081880bad41ea5201d001bf79567a25ccdce409a3d3ba408993dbf9b84d6360d2975cd31790dfac09ec25b2a5ca1171ef808b442f59cde55ae46da0bfa373a05d50607c0ba3ba8d874936e1f52f35b14b8d7dced214abc0258a989d38e83194edcead16b2fa1766224cb8320e135e59375c96b6427a76342aa720e0593cae6674dac7b7ece8c0cfe6b0915c4fc6dc1d373621bd9d3c10ba667ad9129f74aa5780df799bb3a4144e2d182098fed40cbc03329d44af4b31e25de6a87a4968f18f66040e944694de244935323efa46a75067681f58a3e45f04d2e63dfe229ef7a71dfe0c0b5b1d3a97675651afba1fa850825dab89f8951404b1bf76803c724c403b7f180e05feddf6d7af3f8d3f75ba55e74a9b3cb0ede3cb983eb4e8791b5f35a78b410c66bd70f5d5977618cbe2f18b0f14db038b57ad319bf55a4e0e90f56c1b579eff31c57f33c724fd423daa99a1b821b3135e62e7988b558309533f79b990c3e2659d74cf722aa670947cccd3681c2b57c478efc3eb34fa9efd048161b96843e0d4e9d2a7136ba1450487fcedb2c83a9c1556fbcf7511ddda20d2d94679efadedb626c289f842bbfa37911a7c583c9f6418a7920094b31a6ef9018684f67edcc26c17c09241b518bad915f59982c090f5a3369eef2a36506f868dfb1296b3074eba44a444465bcaa71029529e6e4dc3e4896731b0c86709
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208078);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2024-20515");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj04194");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-disc-ZYF2nEEX");
  script_xref(name:"IAVA", value:"2024-A-0544-S");

  script_name(english:"Cisco Identity Services Engine Information Disclosure (cisco-sa-ise-info-disc-ZYF2nEEX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Information Disclosure is affected by a
vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an authenticated, remote attacker to obtain sensitive information from an affected device. This
    vulnerability is due to a lack of proper data protection mechanisms for certain configuration settings. An
    attacker with Read-Only Administrator privileges could exploit this vulnerability by browsing to a page
    that contains sensitive data. A successful exploit could allow the attacker to view device credentials
    that are normally not visible to Read-Only Administrators. (CVE-2024-20515)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-disc-ZYF2nEEX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a5ca572");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj04194");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj04194");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(311);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'9'},   # 3.1P9
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},   # 3.2P7
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'3'}    # 3.3P3
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj04194',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);