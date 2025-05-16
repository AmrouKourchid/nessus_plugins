#TRUSTED 1c7ddc74ed9b1417702374f8b21c68db289982a3093312d2b2928f26b2d872afec7efbba8367fa5a5ab265d4d43a39905abc9e3df895025876f9fa011d1bba6c74fe21c34ad5018b25bba57bc33c1034b5b3057345dde8a89d79e7cad3757f5afb5457f7b77634e9af0fdb16c12ce6db8c8fae3e061b6d3b0a256a3e6bd7c7840d883bfb5dfa9840412460ee545c2f32c2f4463926491786e6dfac8a36cc9b7c32c9011f70490d3bd8f33f972cf55c6ae458566009a5eaa929f3b95cf937fcc982e4f7332bc8afdc119804c2b83b9c1f56e72470db827d699037ce0bc89c431b813e796271011bbb48bf5c1ca3e10cb1c52685a6fc1cbad2f04900264a8215d4e967bfe174fd83a5b997fb782cfe4e0b54ae30e8d19176ed5b59caf7c7ff270381efa8f267cddf3fc02f840ed3182d64608f34532f812c76750f93651e2fea62bed2cf194c326bcb8be82aee656d353a443b1ec63a5511fbeb4a052528db8fde147992a6c004f03458ff4536d0c104e095f71d752a305d55cded1516f782dc2fcfaaa21f84db27e6e946343fddce46b198be80c3909df5af9029245bd0b7f65b968d6064efde43c74a0d4465d16a5af9b84fb9fde3a990dc8494e065c1efe867894d4a88c296026bfbf6581c1a1b8968b3ba1f1c245a0f92957e33582a47538b51e48ad2f55ddc92817367a1d69588cf4743f7e8fd9ae59354e7146cace9d135
#TRUST-RSA-SHA256 748289d146293a359c9656f034cf1c381ba6d3c2bc1cd0de264e06a8ea2e016081eb1f1ffda50adb0c8a55660b7daf895224eef74a55ff57494e0722fc7aa32033926f895ddc9fc063aab46d1ac9176036853f9d324157362536f6090c81db4e03fb2c5484838e010ae74bffbe937fe740ed2b644dab84534ab512e22879d377d2efc32758855454f2b051b2ad3f1fe096b49c888fd83e4c5e89c9d223fe0dfff048be12dd7d18612307b4f97295dacd8ebead5f731c63e85f65815a57095bdcfe6370b95118ae80ad76b80d999c86d450a3c82cd7ca5c944cd9d6990b5823feb112f02d44471da2ac04930f73961d81b9105501645d011e16e83379e76cc38e3902b44231dd178ed4697d0335729a25366e888018dab831853bc92ca9a4323b014c0895990461581e1da2bc2c5b0f356845cdd08d8f0a8cc01b3a8928496a5b598e0bb88b410ce75f79e4245176062a4dda6dc54a3b284e9d8596a7e781c04b6e5e71e85b3b80db513de77854e923a14f9f157f6b4250df9926c8d9d3085f252c61d4b66e15d528258573b6dde7b0c7ebcbd7db6809e5a702754c1cbf3e1bbc1296d8144c412c59972cbcdf2875af30e7dd0af97da9fc1d55bd03cac108dd60726e7acb5378408d09bb5b2fe791c229310072687e8ab1460814ca8877b056c485ff0b8a801439d01fc5fa4c03568561a02c52adc3dba217ccdc4f5c537b8b07
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193039);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2024-20347", "CVE-2024-20352");
  script_xref(name:"IAVA", value:"2024-A-0197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf41263");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf41347");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cem-csrf-suCmNjFr");

  script_name(english:"Cisco Emergency Responder Multiple Vulnerabilities (cisco-sa-cem-csrf-suCmNjFr)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Emergency Responder is affected by multiple vulnerabilities.

  - A vulnerability in Cisco Emergency Responder could allow an authenticated, remote attacker to conduct a
    directory traversal attack, which could allow the attacker to perform arbitrary actions on an affected
    device. This vulnerability is due to insufficient protections for the web UI of an affected system. An
    attacker could exploit this vulnerability by sending crafted requests to the web UI. A successful exploit
    could allow the attacker to perform arbitrary actions with the privilege level of the affected user, such
    as accessing password or log files or uploading and deleting existing files from the system.
    (CVE-2024-20352)

  - A vulnerability in Cisco Emergency Responder could allow an unauthenticated, remote attacker to conduct a
    CSRF attack, which could allow the attacker to perform arbitrary actions on an affected device. This
    vulnerability is due to insufficient protections for the web UI of an affected system. An attacker could
    exploit this vulnerability by persuading a user to click a crafted link. A successful exploit could allow
    the attacker to perform arbitrary actions with the privilege level of the affected user, such as deleting
    users from the device. (CVE-2024-20347)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cem-csrf-suCmNjFr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d4bc131");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf41263");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf41347");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf41263, CSCwf41347");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(23, 352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:emergency_responder");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)");

  exit(0);
}

include('vcf_extras.inc');

var app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

var constraints = [
  # https://software.cisco.com/download/home/286322260/type/282074227/release/12.5(1)SU8
  {'fixed_version': '12.5.1.27900.8'},
  # 14SU4 to be released in 05/2024, fixed ver used here is 14SU3a incremented by .1
  # https://software.cisco.com/download/home/286328120/type/282074227/release/14SU3a
  {'min_version': '14.0', 'fixed_version': '14.0.1.13901.2'}
];

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
