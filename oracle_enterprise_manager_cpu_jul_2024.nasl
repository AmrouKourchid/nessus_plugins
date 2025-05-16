#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id(
    "CVE-2021-37533",
    "CVE-2023-1370",
    "CVE-2023-40167",
    "CVE-2023-48795"
  );
  script_xref(name:"IAVA", value:"2024-A-0425-S");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jul 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by multiple
vulnerabilities as referenced in the July 2024 CPU advisory.

  - Vulnerability in the Oracle Enterprise Manager Base Platform product of Oracle Enterprise Manager 
    (component: Install (Apache Commons Net)). The supported version that is affected is 13.5.0.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise 
    Oracle Enterprise Manager Base Platform. Successful attacks require human interaction from a person other 
    than the attacker. Successful attacks of this vulnerability can result in unauthorized access to critical 
    data or complete access to all Oracle Enterprise Manager Base Platform accessible data. (CVE-2021-37533)

  - Vulnerability in the Oracle Enterprise Manager Base Platform product of Oracle Enterprise Manager 
    (component: Install (json-smart)). The supported version that is affected is 13.5.0.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Enterprise 
    Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle Enterprise Manager Base Platform. 
    (CVE-2023-1370)

  - Vulnerability in the Oracle Application Testing Suite product of Oracle Enterprise Manager (component: 
    Install (Apache Mina SSHD)). The supported version that is affected is 13.3.0.1. Difficult to exploit 
    vulnerability allows unauthenticated attacker with network access via SSH to compromise Oracle 
    Application Testing Suite. Successful attacks of this vulnerability can result in unauthorized creation, 
    deletion or modification access to critical data or all Oracle Application Testing Suite accessible data. 
    (CVE-2023-48795)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37533");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

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
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.22' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
