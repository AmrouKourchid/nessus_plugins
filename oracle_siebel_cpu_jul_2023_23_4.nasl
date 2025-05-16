#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212436);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2022-1471",
    "CVE-2022-40150",
    "CVE-2022-45143",
    "CVE-2023-24998",
    "CVE-2023-28708"
  );

  script_name(english:"Oracle Siebel Server <= 23.4 (July 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Siebel CRM installed on the remote host are affected by multiple vulnerabilities as referenced in
the July 2023 CPU advisory.

  - Vulnerability in the Siebel CRM product of Oracle Siebel CRM (component: EAI (SnakeYAML)). Supported
    versions that are affected are 23.4 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Siebel CRM. Successful attacks of this vulnerability
    can result in takeover of Siebel CRM. (CVE-2022-1471)

  - Vulnerability in the Siebel Apps product of Oracle Siebel CRM (component: Marketing (Apache Commons
    FileUpload)). Supported versions that are affected are 23.4 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Siebel Apps. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Siebel Apps. (CVE-2023-24998)

  - Vulnerability in the Siebel CRM product of Oracle Siebel CRM (component: EAI (Jettison)). Supported
    versions that are affected are 23.4 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Siebel CRM. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Siebel
    CRM. (CVE-2022-40150)

  - Vulnerability in the Siebel CRM product of Oracle Siebel CRM (component: EAI (Apache Tomcat)). Supported
    versions that are affected are 23.4 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Siebel CRM. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Siebel CRM accessible data. (CVE-2022-45143, CVE-2023-28708)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2023csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1471");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:siebel_crm");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_siebel_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Siebel Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Siebel Server');

var constraints = [
  { 'max_version' : '23.4.999', 'fixed_version' : '23.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
