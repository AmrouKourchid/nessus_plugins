#TRUSTED 8031201e67b709a8309183ab615ac72882df33b71d5cc465d7e582b0cf6e9b727b68a3584dc742222dab08fee554ce432bd994145bd2687905f8bef502e7cd1c78d6a56442c11aefdee780c0c70c2b5aafe9e691a8e6ff5cb75212b00a30d2effec4b03e0aa47546b74976f16fa504397ea7635212ab05e8458a6e91af30561eaedd85e5004605361c45bdab8f0999a6122f5cbb1053baa148e6fdca2b63cfad53e7200c285a8c9e8802d15bc1d26cbe2d86210dc537d6e4320ec2f55befcfe6392d2275356078a34b32d3de644cd2fb3245db211d97b79bb1110815eabcc4217672385639517e8924058dcf1f02afd4aa648cbd6d48e420166d80274fc3d439104c81ddca3cd20452a23d13f0e2d459d39f7f4ee63997e14351ae21ed1594e2e9fcc17eadf873864897ddfe197091840829d8dd751e42eff5117d29046e639a3d09acfc8c542617eb2bc0ac25bfdb348d7d186071ea40f7733ebe7bb954f2c3f787678dd3d0502cbcae4e4642b7a3c1b6812ee0e690f32cb3a13a5983a740fe38f659d2695dae2e96447941beebd3ca2b8206f375b779348c61d755753d1220adf7a5ceae5af2273ed493aadff814a41e97ccc66fa85a5bacc99ddf4b63474eebcf66662d228440e3dcd05d5ebe31013d8e1142a70f0688ee0a1d24d3b91b506892a3a9f29bc80d42f62ad254e80ab0af6d03acb5861ca4fb02efa4712db1a8
#TRUST-RSA-SHA256 97d18beb03f67693e68cfe50efd59148328e6ef817d3135f256b4b1d8e77ca0236b37b0fc31a47f4a96505e1def42486760e7854f3d6c28cf38a02df869a3a1428861ce98e7df4e8ebfd0640b02428652889329d5ec8bc6e12fda567ac9d965db3bbc98ac70367c1481b5b05ffdc12c33f1f35921e85e79571977afe82d89acaeb53857e1d734225da8393dcd5b0b788cb70a7d430c5815c52276d66400f5e4bfa7194d695bfedb7c460c6728dd1d746c612317f15195cdce6fb4923549d8c65d21cbc4dfad60a529fa6d8e24317aca621981041a2d176daac6e53080e20f0ccf7a4ce2464fbdf2b648259eedaf182b32cc108321baf8747181882f0aecf23dca4d9d99b2564eb8474d47355109741239e29e51d34685f5b4a751f165b519b1901c8d0a9acbb7a139243546adcc6984ebc28deff91c5ad5a0e6fdf6666349380d94cfdb1ad09dbc1a2f3acfd3cdb2f875e3673353d0c8f8c86a35d80f2cd0fbe82d8a522d3daefcca2853b128fc44b1f15e8c8e862aec177a770a3fc1f39d6f2f22a0e9192945e6583ff8d3493f1eb3af645dac65d8dc7761247e4f07a82b28a8e2fdbd107f35af8260ea8a4421f34b6617ca788ac7d802a00ce6a55dcfc2bb386396e657843ec2134ff9ea97a39c6efabc015de52c0793fb9dc7e4ecd9d8c0f0aad8bdf6915ac0e504849c5e5b328b4b6d1bc32cf1113d333eeacac09b7cb74
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192944);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2024-20334");
  script_xref(name:"IAVA", value:"2024-A-0196");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh57988");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tms-xss-kGw4DX9Y");

  script_name(english:"Cisco TelePresence Management Suite XSS (cisco-sa-tms-xss-kGw4DX9Y)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence Management Suite Cross-Site Scripting is affected by a
vulnerability.

  - A vulnerability in the web-based management interface of Cisco TelePresence Management Suite (TMS) could
    allow a low-privileged, remote attacker to conduct a cross-site scripting (XSS) attack against a user of
    the interface. This vulnerability is due to insufficient input validation by the web-based management
    interface. An attacker could exploit this vulnerability by inserting malicious data in a specific data
    field in the interface. A successful exploit could allow the attacker to execute arbitrary script code in
    the context of the affected interface or access sensitive, browser-based information. (CVE-2024-20334)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tms-xss-kGw4DX9Y
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?530bce04");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh57988");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh57988");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20334");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_management_suite_detect.nbin", "cisco_telepresence_management_suite_installed.nbin");
  script_require_keys("installed_sw/Cisco Telepresence Management Suite");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco Telepresence Management Suite');

var constraints = [{'fixed_version': '15.13.7'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
