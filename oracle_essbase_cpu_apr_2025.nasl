#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234557);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-9143",
    "CVE-2024-13176",
    "CVE-2024-38999",
    "CVE-2021-42575"
  );
  script_xref(name:"IAVA", value:"2025-A-0264");

  script_name(english:"Oracle Essbase Multiple Vulnerabilities (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"A business analytics solution installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Essbase installed on the remote host is missing a security patch from the April 2025
Critical Patch Update (CPU). It is, therefore, affected by:

  - Vulnerability in Oracle Essbase (component: Web Platform (OpenSSL)). The supported version that is 
    affected is 21.7.1.0.0. Easily exploitable vulnerability allows physical access to compromise Oracle
    Essbase. Successful attacks of this vulnerability can result in unauthorized update, insert or delete 
    access to some of Oracle Essbase accessible data as well as unauthorized read access to a subset of Oracle
    Essbase accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of
    Oracle Essbase. (CVE-2024-9143, CVE-2024-13176)

  - Security-in-Depth issue in Oracle Essbase (component: Web Platform (RequireJS)). This vulnerability cannot
    be exploited in the context of this product. (CVE-2024-38999)

  - Security-in-Depth issue in Oracle Essbase (component: Marketplace (jackson-databind)). This vulnerability
    cannot be exploited in the context of this product. (CVE-2021-42575)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9143");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:essbase");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_essbase_installed.nbin");
  script_require_keys("Settings/ParanoidReport", "installed_sw/Oracle Essbase");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'Oracle Essbase');

var constraints = [
  { 'min_version' : '21.7', 'fixed_version' : '21.7.1', 'fixed_display' : '21.7.1.0.0 Patch 37418271 or later'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
