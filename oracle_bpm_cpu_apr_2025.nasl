#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234503);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-25710",
    "CVE-2024-26308",
    "CVE-2024-28168",
    "CVE-2024-47561",
    "CVE-2024-52046"
  );
  script_xref(name:"IAVA", value:"2025-A-0268");

  script_name(english:"Oracle Business Process Management Suite (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Process Management Suite installed on the remote host is affected by multiple
vulnerabilities, as referenced in the April 2025 CPU advisory, as follows:

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Composer, Common (Apache Commons Compress)). The supported version that is affected
    is 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with logon to the
    infrastructure where Oracle Business Process Management Suite executes to compromise Oracle Business
    Process Management Suite. Successful attacks require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Oracle Business Process Management Suite. (CVE-2024-25710)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Plugins (Apache FOP)). Supported versions that are affected are 12.2.1.4.0 and 14.1.2.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    Business Process Management Suite. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Oracle Business Process Management Suite accessible
    data. (CVE-2024-28168)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware (component:
    Composer, Third Party (Apache Avro)). The supported version that is affected is 12.2.1.4.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
    Business Process Management Suite. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Business Process Management Suite accessible data as
    well as unauthorized read access to a subset of Oracle Business Process Management Suite accessible data
    and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Business Process
    Management Suite. (CVE-2024-47561)

  - Vulnerability in the Oracle Business Process Management Suite product of Oracle Fusion Middleware
    (component: Runtime Engine (Apache Mina)). Supported versions that are affected are 12.2.1.4.0 and
    14.1.2.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    HTTP to compromise Oracle Business Process Management Suite. Successful attacks of this vulnerability
    can result in takeover of Oracle Business Process Management Suite. (CVE-2024-52046)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52046");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_process_management_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_bpm_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Process Manager");

  exit(0);
}

include('vcf.inc');
var app_info = vcf::get_app_info(app:'Oracle Business Process Manager');

var constraints = [
  { 'min_version':'12.2.1.4.0', 'fixed_version' : '12.2.1.4.250307' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
