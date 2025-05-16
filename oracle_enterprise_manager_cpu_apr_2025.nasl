#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235062);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/01");

  script_cve_id(
    "CVE-2022-45047", 
    "CVE-2023-1370",
    "CVE-2023-35887", 
    "CVE-2024-52046"
  );
  script_xref(name:"IAVA", value:"2025-A-0267");

  script_name(english:"Oracle Enterprise Manager Cloud Control (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by a vulnerability
as referenced in the April 2025 CPU advisory.

  - Vulnerability in the Oracle Enterprise Manager Base Platform product of Oracle Enterprise Manager 
    (component: Agent Next Gen (Apache Mina SSHD)). Supported versions that are affected are 13.5.0.0.0 and 
    24.1.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    HTTP to compromise Oracle Enterprise Manager Base Platform. Successful attacks of this vulnerability can 
    result in takeover of Oracle Enterprise Manager Base Platform. (CVE-2024-29857)

  - Vulnerability in the Oracle Enterprise Manager Base Platform product of Oracle Enterprise Manager 
    (component: Agent Next Gen (json-smart)). Supported versions that are affected are 13.5.0.0.0 and 
    24.1.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    HTTP to compromise Oracle Enterprise Manager Base Platform. Successful attacks of this vulnerability can 
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle 
    Enterprise Manager Base Platform. (CVE-2023-1370)

  - Vulnerability in the Oracle Enterprise Manager Base Platform product of Oracle Enterprise Manager 
    (component: Agent Next Gen (Apache Mina)). Supported versions that are affected are 13.5.0.0.0 and 
    24.1.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    HTTP to compromise Oracle Enterprise Manager Base Platform. Successful attacks of this vulnerability can 
    result in takeover of Oracle Enterprise Manager Base Platform. (CVE-2024-52046)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45047");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

var constraints = [
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.26', 'fixed_display' : '13.5.0.26 (Patch 37439429)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
