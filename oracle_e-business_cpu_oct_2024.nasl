#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210333);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id(
    "CVE-2024-21206",
    "CVE-2024-21250",
    "CVE-2024-21252",
    "CVE-2024-21258",
    "CVE-2024-21265",
    "CVE-2024-21266",
    "CVE-2024-21267",
    "CVE-2024-21268",
    "CVE-2024-21269",
    "CVE-2024-21270",
    "CVE-2024-21271",
    "CVE-2024-21275",
    "CVE-2024-21276",
    "CVE-2024-21277",
    "CVE-2024-21278",
    "CVE-2024-21279",
    "CVE-2024-21280",
    "CVE-2024-21282"
  );

  script_name(english:"Oracle E-Business Suite (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2024 CPU advisory.

  - Vulnerability in the Oracle Financials product of Oracle E-Business Suite (component: Common Components).
    Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Financials. Successful attacks of
    this vulnerability can result in unauthorized creation, deletion or modification access to critical data
    or all Oracle Financials accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Financials accessible data. (CVE-2024-21282)

  - Vulnerability in the Oracle Sourcing product of Oracle E-Business Suite (component: Auctions). Supported
    versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows low privileged
    attacker with network access via HTTP to compromise Oracle Sourcing. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Oracle Sourcing accessible data as well as unauthorized access to critical data or complete access to all
    Oracle Sourcing accessible data. (CVE-2024-21279)

  - Vulnerability in the Oracle Contract Lifecycle Management for Public Sector product of Oracle E-Business
    Suite (component: Award Processes). Supported versions that are affected are 12.2.3-12.2.13. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    Contract Lifecycle Management for Public Sector. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Oracle Contract Lifecycle
    Management for Public Sector accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Contract Lifecycle Management for Public Sector accessible data. (CVE-2024-21278)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '36944346, 36957442' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '36944346, 37078813' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '36944346, 37078813, 36949119, 37120430' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '36944346, 37078823, 37033978, 37078910, 37120430' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '36944346, 37078836, 37078911, 37120448' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '36944346, 37078855, 37078912, 37120448' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '36944346, 37078855, 37078914, 37120463' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '36944346, 37078877, 37078917, 37120482' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '36944346, 37078884, 37078917, 37120482' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches' : '36944346, 37078893, 37078919, 37120495' },
  { 'min_version' : '12.2.13', 'max_version' : '12.2.13.99999999', 'fix_patches' : '36944346, 37078895, 37078943' },
  { 'min_version' : '12.2.14', 'max_version' : '12.2.14.99999999', 'fix_patches' : '36944346, 37068559' },
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  fix_date:'202410'
);
