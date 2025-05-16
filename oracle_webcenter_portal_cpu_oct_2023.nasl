#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183294);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id(
    "CVE-2021-37714",
    "CVE-2022-45690",
    "CVE-2022-42004",
    "CVE-2023-39022",
    "CVE-2023-34462",
    "CVE-2022-42920"
  );
  script_xref(name:"IAVA", value:"2023-A-0559");
  script_xref(name:"IAVA", value:"2023-A-0563");

  script_name(english:"Oracle WebCenter Portal Multiple Vulnerabilities (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle WebCenter Portal installed on the remote host is missing a security patch from the October 2023
Critical Patch Update (CPU). It is, therefore, affected by multiple vulnerabilities:

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Discussion Forums 
    (OSCORE)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle WebCenter Portal. Successful attacks 
    of this vulnerability can result in takeover of Oracle WebCenter Portal. (CVE-2023-39022)

  - Vulnerability in the Oracle WebCenter Portal product of Oracle Fusion Middleware (component: Development Tools 
    (Apache Commons BCEL)). The supported version that is affected is 12.2.1.4.0.. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Documaker. Successful attacks 
    of this vulnerability can result in takeover of Oracle Documaker. (CVE-2022-42920)

  - Security-in-Depth issue in the Oracle Database Workload Manager (jackson-databind) component of Oracle Database 
    Server. This vulnerability cannot be exploited in the context of this product (CVE-2022-42004)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported 
version number.");
  # https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcbd8a5e");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37714");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39022");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:webcenter_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_webcenter_portal_installed.nbin");
  script_require_keys("installed_sw/Oracle WebCenter Portal");

  exit(0);
}

include('vcf_extras_oracle_webcenter_portal.inc');

var app_info = vcf::oracle_webcenter_portal::get_app_info();

var constraints = [
  {'min_version' : '12.2.1.4', 'fixed_version' : '12.2.1.4.230905'}
];

vcf::oracle_webcenter_portal::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);