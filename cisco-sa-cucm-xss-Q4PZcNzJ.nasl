#TRUSTED 064047d22d1cc41b474896c4786c0fb6c8de458f128b2a170967751dca654520f4a0c1b4ac692a5252166358371e5e288bf63f27a614e5cb95bf00ba981379099cd6c89f009b4b2c7ee535c6781be60dec0e9526dd0cb033402a7a4a46847085898d18ba111d7960f179cf532b2ef862216f58b75af08e3b1aa53e2448a8b6532287d78e570494a8841914dbbdd91a5cd3854b428b114ad61c3f79f635f09f055d10a7750d91a60f57a95745f19029580ed5dc3949402c7cc0784b1dd6003eea663d869b8f23682475a293efcb677b75d55e0684ad6618893b8ac55419afde60b3fd86f77d65bbed522a68893681022758a1a826ec7dc4ffbaf1793dafc0311b33b6ea886fa5cf06d5e9016a95470c094194d9ba51980fce0bcc77e1561c2c5ef5a2b5ebbdb9d854a44cfcbbbc6a4a262bc89061cc0310cb33502164ee392dc0f4af047f9a350080f8a94e4419cd0327bc71194d9994213254d50c53d294ec07813faf57fa60a9fc6b9b2907b7e8c7cf3c5c7acd87349ecb049ec681c507403212f5fc948ee4914c8d0bde1ecdc35ce848df6cf1056d5814a061c1b037b36965a6ae4c4e2ccbaa91f5622bb22f2aaf859bd6f32630390d4301ad80314912c2c4342e03c6ce657d27a79584f4743721581777be34212310933f31170c7fcbf97204952501e27927c4d621be6ad0863be3e6c4466a0af66a2f13a0ce1876973c7e
#TRUST-RSA-SHA256 4172dab7e32283278e1f25c52764fae833d7772d94d1bab0099f7b7a3eabcd59da135124e015e0a3ed111fc3eaeced541538a376f75be713589d60957ce3a07085372fbc7c4d96b9a4add0df935e3fe5ec5a13e8325f5c0ea4971c96608501f8a2a4bb49f0258ad88cf7a66ba3b72c54dcd2922d05ecfd09579dba2bc66581f95b2b8b506e127726ffb9fd2928faf12fde3a4f45a8928cd663cad93edc719f6b0903dba3becdadd219d8ce6fdb4d595ce3ba933a1a1c126cfa7413c4a4bcdb941099e80917c24225777528b8d278c927004d20bcbe50eb2951645971dc29af481f67779b259b493869e3f33b343201eea79c553afe6b893a6d985e0d71a92603cf4ddaa8dd4c22e3d4db0b571ac8e45e48491e54735d03b1506dae54261ba14ccacf644c3c7c8df6d82d5609788e885d424f13edab243c036305c11aa343fa33838bcb150b4a28bfeaa3ecbb5561345c04c5b9c1b16c1cd62a024b2804b7be1bfa8a2b48b8f240ab9a0dfc9404fddcf16fd588b94517ddc646c536566aa99c602195d2c13112b4a3ec7d6ef63f07eac6228e8e31a5b10b2efd8903b33def48379b7c6d0f5be9e57af3ad4cf70bd6eb139d6056452092b73fc3869d27023cdef40d96ce7ce573c9f6e8ddc859e428bafd8186bdf1c17db8c5261218adc16cd5bd66095b4a9c53b25a6da5527261aaf7a70b625a1cbd0e9b27a92853cf1977c4e0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149468);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/02");

  script_cve_id(
    "CVE-2021-1380",
    "CVE-2021-1407",
    "CVE-2021-1408",
    "CVE-2021-1409"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu52262");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21040");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv28764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv35159");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw71918");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14158");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx14178");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-xss-Q4PZcNzJ");
  script_xref(name:"IAVA", value:"2021-A-0162");

  script_name(english:"Cisco Unified Communications Manager XSS (cisco-sa-cucm-xss-Q4PZcNzJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of cisco unified communications manager installed on the remote host is prior to version 14. It is,
therefore, affected by multiple cross-site scripting vulnerabilities.

Multiple vulnerabilities in the web-based management interface of Cisco Unified CM, could allow an unauthenticated, remote
attacker to conduct an XSS attack against an interface user. An attacker could exploit this vulnerability by persuading
an interface user to click a crafted link. A successful exploit could allow the attacker to execute arbitrary script
code in the context of the affected interface or access sensitive browser-based information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-xss-Q4PZcNzJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e61edeb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu52262");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21040");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv28764");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv35159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw71918");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14158");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx14178");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu52262, CSCvv21040, CSCvv28764, CSCvv35159,
CSCvw71918, CSCvx14158, CSCvx14178");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1409");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

# https://software.cisco.com/download/home/286328117/type/286319236/release/14
var vuln_ranges = [{'min_ver' : '0.0',  'fix_ver' : '14.0.1.10000.20'}];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvu52262, CSCvv21040, CSCvv28764, CSCvv35159, CSCvw71918, CSCvx14158, CSCvx14178',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
product_info:product_info, 
reporting:reporting, 
vuln_ranges:vuln_ranges
);