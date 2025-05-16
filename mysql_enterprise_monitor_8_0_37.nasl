#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189239);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2023-5363", "CVE-2023-46589", "CVE-2023-50164");
  script_xref(name:"IAVA", value:"2024-A-0034-S");

  script_name(english:"Oracle MySQL Enterprise Monitor (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2024 CPU advisory.

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/C++ (OpenSSL)). 
    Supported versions that are affected are 8.2.0 and prior. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Connectors. 
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete 
    access to all MySQL Connectors accessible data. (CVE-2023-5363)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General 
    (Apache Tomcat)). Supported versions that are affected are 8.0.36 and prior. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in unauthorized creation, 
    deletion or modification access to critical data or all MySQL Enterprise Monitor accessible data.
    (CVE-2023-46589)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General 
    (Apache Struts)). Supported versions that are affected are 8.0.36 and prior. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise 
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in takeover of MySQL 
    Enterprise Monitor. (CVE-2023-50164)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.37' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
