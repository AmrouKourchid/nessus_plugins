#TRUSTED 10a5baf7d1da9273ac4f414aabd3af1eeba6df8a5c158b4be65bfac72204a5958e4552c6ee795e28ce34696666599289c1f37a5dafef1e20a6515766d8d685e07f151b202e9adcc88bf9f830d39bdb4c02b1e0d7373187c22b8cec756303f299abd3a61218c9760852bc4a92f78aeea16ea0e16e962ab6536f7bce90b127839bf9b9781ef3d8babc9a37d06d1d71f70275ab3ea79900ee33e71c58fe9d4931dda6a3b7d662f3461cfe6468d62a3cd725f84410b7e22c29382a0f86cecefd92becc97d84613d73d4210b78322f94af6b36aba1d15e315abb99c4749190ea26ac1a3c46382987ef0e0992313d7f58cad2447bf9244a2aec1fd74b5be3c8dea119d88cb7013c1bcf1374780d90e36e6e9ea45c4760904495dae88212f204ac4912846b6f8f65a7bf9aaa99799591f7b26e4b57937d2f51db4dfc5b3c60e99da21665a5b0de47b356f72943fe36c47a510084de4e7a827697c03ae03966a90e8bf53b6eaad44f7140b3ed5a31b7f8549fbbf588d4f30d6d3409c0a9dd4532997bb99394370daee6cefa0ed231db8f9d0ddb30e66336200fabaa4af9c43e14d559910f0b7938b4594430cab72110e723404e614fa96d4a25bf788a3a03cb57306dca6034b94dd31f179349fdf7b9b3d18b646884b5e738b7378c4e1c6fd35b24ebb58dfdf8d2d5d71292b64ca4d8ee50c21f90687efb7a799858d82b5ca5a8a68360f
#TRUST-RSA-SHA256 55e721c62eac7bf89f8862a1538ba8e71e7e29ba44f28dd937a57dd084768211e23664ba46291b1418d985456da049ec71dac0209a43af1abaab0abcf5abc9fd2e1d132f5bf9c1a60f1f72cca48a9ef6c186e886bd597ebee16c3bd96d386fd115aed80cac4b4c5b4dc4a1d8454d2f4bde233c4eb1009407755c2b686a2440fed15509fe4dfec6d39aed32b3a8d41291d802262854efb9f4978c10e91e3c0f4347acfc5801d0194e5a305f242ed4143f455b13b409dcf0d938c00e026736e21196e4885200e54dc050115af8bbc0502929b70f8230c0fcf17e121f70a395d21d3b58acb9518e72b933ec763304f6e70f0eccfcf308d0f7d9bc16a92cbc7ecf122b121645de43327d47f967cac23bd08fc160eeec8e86f66db287f8c9b8d6744284e73a58c7560b1693feccb1318559ebc117e0765cbb1bd9ddd16efc73c45dbe0903033415287dde4b79ad38886e350d691fbcdf1a09df642e8d2e65ab0be0cd07f360db543c5e5e5fc8e8a50b7a9d2e2b3906a283f1901f410fafbeb52c675c0dddf3efb0971dc64f86664239f7d3ed6277248418a8bf9ae5746185b926c3e10431f73b4e83e9ab99cee387f5fcaae2743c03dca50316ac7ef34503208c4ea54e10a74cb229312556f14467dd3aad1c56a3478fcdf96d293e04a047079203e3a09f87245299060398efd1a5a33f8b5e14942b16f5d91365d8f0e808e886d593
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205336);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/12");

  script_cve_id("CVE-2024-20419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk21399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cssm-auth-sLw3uhUy");

  script_name(english:"Cisco Smart Software Manager On-Prem Password Change (cisco-sa-cssm-auth-sLw3uhUy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Smart Software Manager On-Prem Password Change is affected by a
vulnerability.

  - A vulnerability in the authentication system of Cisco Smart Software Manager On-Prem (SSM On-Prem) could
    allow an unauthenticated, remote attacker to change the password of any user, including administrative
    users. This vulnerability is due to improper implementation of the password-change process. An attacker
    could exploit this vulnerability by sending crafted HTTP requests to an affected device. A successful
    exploit could allow an attacker to access the web UI or API with the privileges of the compromised user.
    (CVE-2024-20419)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cssm-auth-sLw3uhUy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce51e5e3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk21399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk21399");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20419");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(620);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:smart_software_manager_on-prem");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_smart_software_manager_web_interface_detect.nbin");
  script_require_keys("Cisco Smart Software Manager On-Prem");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::cisco_ssm::initialize();

var app_info = vcf::combined_get_app_info(app:'Cisco Smart Software Manager On-Prem');

var constraints = [
  {'fixed_version': '8-202212'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
