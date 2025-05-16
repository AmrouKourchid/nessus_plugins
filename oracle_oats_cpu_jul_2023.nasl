#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-23305", "CVE-2022-42003", "CVE-2023-24998");
  script_xref(name:"IAVA", value:"2023-A-0364-S");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Application Testing Suite (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Application Testing Suite installed on the remote host is affected by multiple vulnerabilities as
referenced in the July 2023 CPU advisory:

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component:
    Load Testing for Web Apps (Apache Log4j)). The supported version that is affected is 13.3.0.1. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Application Testing Suite. Successful attacks of this vulnerability can result in takeover of
    Oracle Application Testing Suite. (CVE-2022-23305)

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component:
    Load Testing for Web Apps (jackson-databind)). The supported version that is affected is 13.3.0.1. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Application Testing Suite. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Application Testing Suite.
    (CVE-2022-42003)

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component:
    Load Testing for Web Apps (Apache Commons FileUpload)). The supported version that is affected is
    13.3.0.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to
    compromise Oracle Application Testing Suite. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Application
    Testing Suite. (CVE-2023-24998)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_testing_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_application_testing_suite_installed.nbin");
  script_require_keys("installed_sw/Oracle Application Testing Suite");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_oats::get_app_info();

var patches_to_report;
var patches_to_check;
if (get_kb_item('SMB/Registry/Enumerated'))
{
  patches_to_report = make_list('35579537');
}
else
{
  patches_to_report = make_list('35579537', '34395275');
  patches_to_check = make_list('34395275');
}


var constraints = [
  { 'min_version' : '13.3.0.1', 'fixed_version' : '13.3.0.1.561' }
];

vcf::oracle_oats::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints,
  patches_to_report:patches_to_report,
  patches_to_check:patches_to_check
);

