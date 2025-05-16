#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189242);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/19");

  script_cve_id(
    "CVE-2022-42003",
    "CVE-2023-1436",
    "CVE-2023-33201",
    "CVE-2024-20916",
    "CVE-2024-20917"
  );
  script_xref(name:"IAVA", value:"2024-A-0029");

  script_name(english:"Oracle Enterprise Manager Cloud Control (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.5.0.0 version of Enterprise Manager Base Platform product of Oracle Enterprise Manager installed on the remote
host is affected by multiple vulnerabilities as referenced in the January 2024 CPU advisory:

  - Vulnerability in the Agent Next Gen (jackson-databind) and Extensibility Framework (jackson-databind)
  components of Enterprise Manager Base Platform. Easily exploitable vulnerability allows an unauthenticated 
  attacker with network access via HTTP to compromise Oracle Enterprise Manager Base Platform. Successful
  attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of Oracle Enterprise Manager Base Platform. (CVE-2022-42003)

  - Vulnerability in the Agent Next Gen (Jettison) component of Enterprise Manager Base Platform. Easily
  exploitable vulnerability allows an unauthenticated attacker with network access via HTTP to compromise 
  Oracle Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized
  ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Enterprise Manager Base
  Platform. (CVE-2023-1436)

  - Vulnerability in the Log Management component of Enterprise Manager Base Platform. Difficult to exploit
  vulnerability allows an unauthenticated attacker with network access via HTTP to compromise Oracle
  Enterprise Manager Base Platform. Successful attacks require human interaction from a person other than the
  attacker and while the vulnerability is in Oracle Enterprise Manager Base Platform, attacks may 
  significantly impact additional products (scope change). Successful attacks of this vulnerability can result
  in  unauthorized access to critical data or complete access to all Oracle Enterprise Manager Base Platform
  accessible data as well as  unauthorized update, insert or delete access to some of Oracle Enterprise
  Manager Base Platform accessible data and unauthorized ability to cause a partial denial of service (partial
  DOS) of Oracle Enterprise Manager Base Platform. (CVE-2024-20917)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:M/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20916");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

var constraints = [
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.19', 'fixed_display' : '13.5.0.19 (Patch 35861059)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
