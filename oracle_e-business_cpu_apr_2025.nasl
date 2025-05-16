#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234553);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-38828",
    "CVE-2025-21582",
    "CVE-2025-30692",
    "CVE-2025-30707",
    "CVE-2025-30708",
    "CVE-2025-30711",
    "CVE-2025-30716",
    "CVE-2025-30717",
    "CVE-2025-30718",
    "CVE-2025-30720",
    "CVE-2025-30726",
    "CVE-2025-30727",
    "CVE-2025-30728",
    "CVE-2025-30730",
    "CVE-2025-30731",
    "CVE-2025-30732"
  );
  script_xref(name:"IAVA", value:"2025-A-0266");

  script_name(english:"Oracle E-Business Suite (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2025 CPU advisory.

  - Vulnerability in the Oracle Scripting product of Oracle E-Business Suite (component: iSurvey
    Module). Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Scripting. Successful attacks
    of this vulnerability can result in takeover of Oracle Scripting. (CVE-2025-30727)

  - Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Core). Supported
    versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Oracle Configurator. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all Oracle
    Configurator accessible data. (CVE-2025-30728)

  - Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component:
    Core). Supported versions that are affected are 12.2.5-12.2.14. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object
    Library. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle Application Object Library. (CVE-2025-30730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30727");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

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

var constraints = [
  { 'min_version' : '12.2.3',  'max_version' :'12.2.3.999999', 'fix_patches' : '37531055, 36957442, 27120099, 37614928, 32636352'},
  { 'min_version' : '12.2.4',  'max_version' :'12.2.4.999999', 'fix_patches' : '37531055, 37078798, 32750949, 32636352, 37327694, 37614928, 37577879, 34979060'},
  { 'min_version' : '12.2.5',  'max_version' :'12.2.5.999999', 'fix_patches' : '37531055, 37078813, 36949119, 37120399, 32750949, 36453170, 34979060, 37620005, 37327694, 37614928, 37577883'},
  { 'min_version' : '12.2.6',  'max_version' :'12.2.6.999999', 'fix_patches' : '37531055, 37078823, 34870379, 37078910, 37120430, 34979060, 36560216, 25229413, 37620005, 37327694, 37614928, 37577884, 37033978'},
  { 'min_version' : '12.2.7',  'max_version' :'12.2.7.999999', 'fix_patches' : '37531055, 37078911, 34870379, 3723736, 35362524, 34979060, 36560216, 37078836, 37120448, 25229413, 37620005, 37327694, 37614928, 37424919' },
  { 'min_version' : '12.2.8',  'max_version' :'12.2.8.999999', 'fix_patches' : '37531055, 37078843, 34870379, 37078912, 33623398, 35362524, 34979060, 36560216, 37120448, 37620005, 37327694, 37614928, 37424931'},
  { 'min_version' : '12.2.9',  'max_version' :'12.2.9.999999', 'fix_patches' : '37531055, 37078855, 37078914, 37120463, 35362524, 34979060, 33457157, 36560216, 30448458, 37620005, 37327694, 37614928, 37425373'},
  { 'min_version' : '12.2.10', 'max_version' :'12.2.10.999999', 'fix_patches' : '37531055, 37078877, 37078915, 35362524, 34979060, 33457157, 36560216, 37120482, 30448458, 37620005, 37327694, 37614928, 37425380'},
  { 'min_version' : '12.2.11', 'max_version' :'12.2.11.999999', 'fix_patches' : '37531055, 37078884, 37078917, 35362524, 34979060, 33457157, 36560216, 37120482, 30448458, 37620005, 37327694, 37614928, 37425383'},
  { 'min_version' : '12.2.12', 'max_version' :'12.2.12.999999', 'fix_patches' : '37531055, 37078893, 37078919, 37120495, 35362524, 34979060, 33457157, 36560216, 37288039, 30448458, 37620005, 37327694, 37614928, 37425389'},
  { 'min_version' : '12.2.13', 'max_version' :'12.2.13.999999', 'fix_patches' : '37531055, 37078895, 37078943, 34979060, 33457157, 30448458, 36560216, 37287000, 37425397, 37620005, 37327694, 37614928'},
  { 'min_version' : '12.2.14', 'max_version' :'12.2.14.999999', 'fix_patches' : '37531055, 37068559, 34979060, 33457157, 30448458, 37614928'},
  { 'min_version' : '12.2.15', 'max_version' :'12.2.15.999999', 'fix_patches' : '37531055, 33457157, 30448458' }
];

vcf::oracle_ebusiness::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, fix_date:'202504');
