#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214592);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2025-21489",
    "CVE-2025-21506",
    "CVE-2025-21516",
    "CVE-2025-21541"
  );
  script_xref(name:"IAVA", value:"2025-A-0045-S");

  script_name(english:"Oracle E-Business Suite (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the January 2025 CPU advisory.

  - Vulnerability in the Oracle Customer Care product of Oracle E-Business Suite (component: Service
    Requests). Supported versions that are affected are 12.2.5-12.2.13. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle Customer Care. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Customer Care accessible data as well as unauthorized access to critical data
    or complete access to all Oracle Customer Care accessible data. (CVE-2025-21516)

  - Vulnerability in the Oracle Project Foundation product of Oracle E-Business Suite (component: Technology
    Foundation). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle Project Foundation.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Project Foundation accessible data as well as unauthorized access to
    critical data or complete access to all Oracle Project Foundation accessible data. (CVE-2025-21506)

  - Vulnerability in the Oracle Advanced Outbound Telephony product of Oracle E-Business Suite (component:
    Region Mapping). Supported versions that are affected are 12.2.3-12.2.10. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Advanced Outbound
    Telephony. Successful attacks require human interaction from a person other than the attacker and while
    the vulnerability is in Oracle Advanced Outbound Telephony, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Advanced Outbound Telephony accessible data as well as
    unauthorized read access to a subset of Oracle Advanced Outbound Telephony accessible data.
    (CVE-2025-21489)

  - Vulnerability in the Oracle Workflow product of Oracle E-Business Suite (component: Admin Screens and
    Grants UI). Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Oracle Workflow. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle
    Workflow accessible data as well as unauthorized read access to a subset of Oracle Workflow accessible
    data. (CVE-2025-21541)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

#TODO: Update constraints accordingly based on Oracle CPU data
var constraints = [
  { 'min_version' : '12.2.3',  'max_version' :'12.2.3.999999', 'fix_patches' : '37237361, 36957442, 27120099'},
  { 'min_version' : '12.2.4',  'max_version' :'12.2.4.999999', 'fix_patches' : '37237361, 37078798, 32750949, 32636352'},
  { 'min_version' : '12.2.5',  'max_version' :'12.2.5.999999', 'fix_patches' : '37237361, 37078813, 36949119, 37120399, 32750949, 36453170, 34979060'},
  { 'min_version' : '12.2.6',  'max_version' :'12.2.6.999999', 'fix_patches' : '37237361, 37078823, 34870379, 37078910, 37120430, 34979060, 36560216, 25229413'},
  { 'min_version' : '12.2.7',  'max_version' :'12.2.7.999999', 'fix_patches' : '37237361, 37078911, 34870379, 3723736, 35362524, 34979060, 36560216, 37078836, 37120448, 25229413' },
  { 'min_version' : '12.2.8',  'max_version' :'12.2.8.999999', 'fix_patches' : '37237361, 37078843, 34870379,37078912, 33623398, 35362524, 34979060, 36560216, 37120448'},
  { 'min_version' : '12.2.9',  'max_version' :'12.2.9.999999', 'fix_patches' : '37237361, 37078855, 37078914, 37120463, 35362524, 34979060, 33457157, 36560216, 30448458, 30448458'},
  { 'min_version' : '12.2.10', 'max_version' :'12.2.10.999999', 'fix_patches' : '37237361, 37078877, 37078915, 35362524, 34979060, 33457157, 36560216, 37120482, 30448458, 30448458'},
  { 'min_version' : '12.2.11', 'max_version' :'12.2.11.999999', 'fix_patches' : '37237361, 37078884, 37078917, 35362524, 34979060, 33457157, 36560216, 30448458, 37120482, 30448458'},
  { 'min_version' : '12.2.12', 'max_version' :'12.2.12.999999', 'fix_patches' : '37237361, 37078893, 37078919, 37120495, 35362524, 34979060, 30448458, 33457157, 36560216, 37288039} 30448458'},
  { 'min_version' : '12.2.13', 'max_version' :'12.2.13.999999', 'fix_patches' : '37237361, 37078895, 37078943,  34979060, 33457157, 30448458, 36560216, 37287000, 30448458'},
  { 'min_version' : '12.2.14', 'max_version' :'12.2.14.999999', 'fix_patches' : '37237361, 37068559, 34979060, 33457157, 30448458, 30448458'},
  { 'min_version' : '12.2.15', 'max_version' :'12.2.15.999999', 'fix_patches' : '37237361, 33457157, 30448458, 30448458' }
];

vcf::oracle_ebusiness::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, fix_date:'202501');
