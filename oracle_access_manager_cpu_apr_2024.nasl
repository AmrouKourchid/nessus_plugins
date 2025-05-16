#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193591);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id(
    "CVE-2019-0231",
    "CVE-2022-24329",
    "CVE-2023-37536",
    "CVE-2023-37536",
    "CVE-2023-37536"
  );

  script_name(english:"Oracle Access Manager (Apr 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.2.1.4.0 versions of Access Manager installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2024 CPU advisory.

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Webserver
    Plugin (Apache Xerces-C++)). The supported version that is affected is 12.2.1.4.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Access
    Manager. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. (CVE-2023-37536)

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Third Party
    (Apache Mina)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via TLS to compromise Oracle Access Manager.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle Access Manager accessible data. (CVE-2019-0231)

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Third Party
    (JetBrains Kotlin)). The supported version that is affected is 12.2.1.4.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access
    Manager. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of Oracle Access Manager accessible data. (CVE-2022-24329)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24329");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-37536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:access_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Access Manager');

var constraints = [
  { 'min_version' : '12.2.1.4.0', 'fixed_version' : '12.2.1.4.240328' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
