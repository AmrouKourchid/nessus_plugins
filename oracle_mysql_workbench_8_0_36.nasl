#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189238);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2023-2283",
    "CVE-2023-5363",
    "CVE-2023-41105",
    "CVE-2022-46908"
  );
  script_xref(name:"IAVA", value:"2024-A-0034-S");

  script_name(english:"Oracle MySQL Workbench < 8.0.36 (January 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a Use After Free vulnerability.");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Workbench installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2024 CPU advisory.

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (libssh)). 
    Supported versions that are affected are 8.0.34 and prior. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via MySQL Workbench to compromise MySQL Workbench. 
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to 
    some of MySQL Workbench accessible data as well as unauthorized read access to a subset of MySQL 
    Workbench accessible data. (CVE-2023-2283)

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (OpenSSL)). 
    Supported versions that are affected are 8.0.34 and prior. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via MySQL Workbench to compromise MySQL Workbench. 
    Successful attacks of this vulnerability can result in unauthorized access to critical data or 
    complete access to all MySQL Workbench accessible data. (CVE-2023-5363)

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: Workbench (Python)). 
    Supported versions that are affected are 8.0.34 and prior. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via MySQL Workbench to compromise MySQL Workbench. 
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification 
    access to critical data or all MySQL Workbench accessible data.(CVE-2023-41105)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle MySQL Workbench version 8.0.36 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5363");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_workbench");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql_workbench");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_workbench_win_installed.nbin");
  script_require_keys("installed_sw/MySQL Workbench");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Workbench');
var constraints = [{'fixed_version': '8.0.36'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);