#TRUSTED 6ba69cae07dfb12c7e327c7b5a284f2ac0503d2b76477d94a4884738231c15ca0703b67c0087c4120705ada5c05d5523a399ddd63fb7a3402c4922997c3a53582810ea4a51514c19e1b55c706687a400dc7b94360be090b0c6b0065a89692b42817aa2e7679f117b86ec9d7b7454bc7b1c565b79aba97f140619c9ee6aa31d1567678a614d14ceb4061174883833b2f9be35aa928f13dc50f54003c4b762183ae73eaead3da727c8fe397590373573ddf100e59b7d78c5db3a62f6a019ee03f0ee3c1d1333207031a0638422b9bae5df4cf922651bda2e8d9d9bdf15ebeba8fe6ee96f5352d1e62f4a336f85d02afec02ddaccbbe9b898d94663018d5c5613191598162b089aca0dda64273c2ba9ab31159fc234182d2ae950056276c4af5c2c193aa2897ebfc6b90b7c830510906bb29b336f76d413b23492adf1f51421b1874f9d20e2725b8d39e29787bb8b9aac5d733c3a9a2a644bdb29ece2a5dfecdd923153689804159c24674ea9c7eea7e8a7c4e5241fd522500a9a49d41c755f2044adc953801e341bcf059e9366e8bad177fdbdaf0da401c13897ef27c9e3320a572d722c28487693c64349f5948371683b207c9102344510766addf9d410e4add2e0d6c73baf97fbf7049345ef57726cc425146ca68594f97967bbed411761df83f6ef0f6a773c9e33943fc32e6e8ac4635eb2e83a8242722f0bb4f2a8e8490972
#TRUST-RSA-SHA256 a8ee6544ecb99350a2f42e53ac64f88f5aa708292ecd8172c499fc5e80ba09eb88c66f864552f6f6682b11f0ef481b12a6602e85a27a3a54f956429c7d1dba8857a1ee43ed9005037fc3e43151611fdd698af874dd515b6041b1c824040a4c4d5f3e4a845a4ca12547b2113f9c8eadc9321b09736ee72a693a785cf958c334aa35584424422dc17797427c9540ff10125724206efa6b181b17d46ae4ef9deb5547cbd9f618ca3caee40ab504c962bff2d14cac6d6f9f915fafa5710dc70bc625e088b66c700c0c77736dc1dc632f533460d36ce45db13592dc85a6ccf3e7770bafc7b39f7eb13d806c1a505c235a3401d0d46ea85895f0f07a97f2e82f22ca0684282a05d8780189889009d2e68318a9c56c55d525598136b5e8c0b28c0faf4c4403ce33706bd3ea6eab4e8afe678062b5c177d36b0075c0c129fa6bde6c2bce29d5da75dc6f6f9f635d978e87b20d489571c82f5479e993f3e4bee5e2a8048c77004d40ebbeb2c16d577eff0522953fca5dfd326e993b226f18f5a72cae11c763b4c46c45c7d2c9e17034f89b2eac2f6d082f35735eaec37d63e4274d0b1c42d6206f50cbf492a9c394a273b024d2b56f58f75fbe49bc1a31048331430c4aba221382f397fc2f6c098419c8548332204ce0cebdb78403dce028e771a52510accde921a79ed81ebc48217a107cd8e4c852b95cc9db718f9755b0a8cadd238cff
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206882);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2024-20417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj94294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj94297");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj94305");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj94315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-rest-5bPKrNtZ");
  script_xref(name:"IAVA", value:"2024-A-0414-S");

  script_name(english:"Cisco Identity Services Engine REST API Blind SQLi (cisco-sa-ise-rest-5bPKrNtZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine REST API Blind SQL Injection Vulnerabilities is
affected by a Blind SQL Injection (SQLi) vulnerability.

  - Multiple vulnerabilities in the REST API of Cisco Identity Services Engine (ISE) could allow an
    authenticated, remote attacker to conduct blind SQL injection attacks. These vulnerabilities are due to
    insufficient validation of user-supplied input in REST API calls. An attacker could exploit these
    vulnerabilities by sending crafted input to an affected device. A successful exploit could allow the
    attacker to view or modify data on the affected device. (CVE-2024-20417)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-rest-5bPKrNtZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7be112f7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj94294");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj94297");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj94305");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj94315");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj94294, CSCwj94297, CSCwj94305, CSCwj94315");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20417");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

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
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'}, # At the time of plugin release 3.2 Patch 7 is slated for release September 2024
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'4'}, # At the time of plugin release 3.3 Patch 4 is slated for release October 2024
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'sqli':TRUE},
  'bug_id'        , 'CSCwj94294, CSCwj94297, CSCwj94305, CSCwj94315',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
