#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210344);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2024-38998", "CVE-2024-38999");

  script_name(english:"Oracle Business Process Management Suite (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by a
vulnerability, as referenced in the October 2024 CPU advisory.

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
  (component: Composer (RequireJS)). The supported version that is affected is 12.2.1.4.0. Easily exploitable
  vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Business 
  Process Management Suite. Successful attacks of this vulnerability can result in unauthorized access to
  critical data or complete access to all Oracle Business Process Management Suite accessible data as well as
  unauthorized update, insert or delete access to some of Oracle Business Process Management Suite accessible
  data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Business Process
  Management Suite. (CVE-2024-38998, CVE-2024-38999)

Note that Nessus has not tested for this issue but has instead relied only on the application's 
self-reported version number.");
  # https://www.oracle.com/security-alerts/cpuoct2024.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f26efacf");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38998");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38999");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

var constraints = [
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.240919' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
