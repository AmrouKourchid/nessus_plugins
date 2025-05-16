#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214531);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-38816", "CVE-2024-38819");

  script_name(english:"Oracle Identity Manager (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 versions of Identity Manager installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2025 CPU advisory.

  - Vulnerability in the Oracle Identity Manager product of Oracle Fusion Middleware (component: Installer 
    (Spring Framework)). The supported version that is affected is 12.2.1.4.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Identity 
    Manager. Successful attacks of this vulnerability can result in unauthorized access to critical data or 
    complete access to all Oracle Identity Manager accessible data. (CVE-2024-38819)
    
  - Applications serving static resources through the functional web frameworks WebMvc.fn or WebFlux.fn are
    vulnerable to path traversal attacks. An attacker can craft malicious HTTP requests and obtain any file on
    the file system that is also accessible to the process in which the Spring application is running.
    Specifically, an application is vulnerable when both of the following are true: * the web application uses
    RouterFunctions to serve static resources * resource handling is explicitly configured with a
    FileSystemResource location However, malicious requests are blocked and rejected when any of the following
    is true: * the Spring Security HTTP Firewall https://docs.spring.io/spring-
    security/reference/servlet/exploits/firewall.html is in use * the application runs on Tomcat or Jetty
    (CVE-2024-38816)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38819");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Identity Manager');

#TODO: Update constraints accordingly based on Oracle CPU data
var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.241211' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
