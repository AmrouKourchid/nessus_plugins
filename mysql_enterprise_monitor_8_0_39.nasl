#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202597);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id("CVE-2024-22257", "CVE-2024-22262", "CVE-2024-24549");
  script_xref(name:"IAVA", value:"2024-A-0449-S");

  script_name(english:"Oracle MySQL Enterprise Monitor (Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2024 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor component Spring Security. A remote 
    unauthenticated attacker could gain unauthorized access to critical data or complete 
    access to all MySQL Enterprise Monitor accessible data as well as unauthorized
    update, insert or delete access to some of MySQL Enterprise Monitor accessible data. 
    (CVE-2024-22257)

  - Vulnerability in the MySQL Enterprise Monitor component Spring 
    Framework. Supported versions that are affected are 8.0.38 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols 
    to compromise MySQL Enterprise Monitor. Successful attacks require human interaction from 
    a person other than the attacker. Successful attacks of this vulnerability can result 
    in unauthorized creation, deletion or modification access to critical data or all MySQL 
    Enterprise Monitor accessible data as well as unauthorized access to critical data or 
    complete access to all MySQL Enterprise Monitor accessible data. (CVE-2024-22262)

  - Vulnerability in the MySQL Enterprise Monitor component 
    Apache Tomcat. A unauthenticated attacker with network access via multiple protocols 
    to compromise MySQL Enterprise Monitor. Successful attacks of this vulnerability can 
    result in unauthorized ability to cause a hang or frequently repeatable crash MySQL 
    Enterprise Monitor. (CVE-2024-24549)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22262");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-22257");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_version' : '8.0', 'fixed_version' : '8.0.39' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
