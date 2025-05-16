#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178625);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id(
    "CVE-2021-34429",
    "CVE-2021-36373",
    "CVE-2021-36374",
    "CVE-2021-41184",
    "CVE-2022-23437"
  );
  script_xref(name:"IAVA", value:"2023-A-0365-S");
  script_xref(name:"IAVA", value:"2023-A-0559");

  script_name(english:"Oracle Business Process Management Suite (Jul 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by multiple
vulnerabilities, as referenced in the July 2023 CPU advisory, including:

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Runtime Engine (Apache Xerces2 Java)). The supported version that is affected is
    12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    HTTP to compromise Oracle Business Process Management Suite. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle Business
    Process Management Suite. (CVE-2022-23437)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: BPM Studio (jQueryUI)). The supported version that is affected is 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Oracle Business Process Management Suite. Successful attacks require human interaction from a person
    other than the attacker and while the vulnerability is in Oracle Business Process Management Suite,
    attacks may significantly impact additional products (scope change). Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle Business
    Process Management Suite accessible data as well as unauthorized read access to a subset of Oracle
    Business Process Management Suite accessible data. (CVE-2021-41184)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Installer (Apache Ant)). The supported version that is affected is 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle
    Business Process Management Suite executes to compromise Oracle Business Process Management Suite.
    Successful attacks require human interaction from a person other than the attacker. Successful attacks of
    this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle Business Process Management Suite. (CVE-2021-36374)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34429");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-41184");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

var constraints = [
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.230530' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
