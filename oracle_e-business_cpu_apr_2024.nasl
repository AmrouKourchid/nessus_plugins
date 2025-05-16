#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193570);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2024-20990",
    "CVE-2024-21016",
    "CVE-2024-21017",
    "CVE-2024-21018",
    "CVE-2024-21019",
    "CVE-2024-21020",
    "CVE-2024-21021",
    "CVE-2024-21022",
    "CVE-2024-21023",
    "CVE-2024-21024",
    "CVE-2024-21025",
    "CVE-2024-21026",
    "CVE-2024-21027",
    "CVE-2024-21028",
    "CVE-2024-21029",
    "CVE-2024-21030",
    "CVE-2024-21031",
    "CVE-2024-21032",
    "CVE-2024-21033",
    "CVE-2024-21034",
    "CVE-2024-21035",
    "CVE-2024-21036",
    "CVE-2024-21037",
    "CVE-2024-21038",
    "CVE-2024-21039",
    "CVE-2024-21040",
    "CVE-2024-21041",
    "CVE-2024-21042",
    "CVE-2024-21043",
    "CVE-2024-21044",
    "CVE-2024-21045",
    "CVE-2024-21046",
    "CVE-2024-21048",
    "CVE-2024-21071",
    "CVE-2024-21072",
    "CVE-2024-21073",
    "CVE-2024-21074",
    "CVE-2024-21075",
    "CVE-2024-21076",
    "CVE-2024-21077",
    "CVE-2024-21078",
    "CVE-2024-21079",
    "CVE-2024-21080",
    "CVE-2024-21081",
    "CVE-2024-21086",
    "CVE-2024-21088",
    "CVE-2024-21089"
  );

  script_name(english:"Oracle E-Business Suite (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2024 CPU advisory.

  - Vulnerability in the Oracle Workflow product of Oracle E-Business Suite (component: Admin Screens and
    Grants UI). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability
    allows high privileged attacker with network access via HTTP to compromise Oracle Workflow. While the
    vulnerability is in Oracle Workflow, attacks may significantly impact additional products (scope change).
    Successful attacks of this vulnerability can result in takeover of Oracle Workflow. (CVE-2024-21071)

  - Vulnerability in the Oracle Production Scheduling product of Oracle E-Business Suite (component: Import
    Utility). Supported versions that are affected are 12.2.4-12.2.12. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Production Scheduling.
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification
    access to critical data or all Oracle Production Scheduling accessible data. (CVE-2024-21088)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Campaign LOV).
    Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle Marketing. Successful attacks
    of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle
    Marketing accessible data. (CVE-2024-21079)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21071");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-21030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '36271505, 36050661, 36462542' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '36271505, 36289280, 36050661, 36462542' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '36271505, 36086578, 36050661, 36337060' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 36337060' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 36337060' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 35951803, 36337068, 35828458' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 35951812, 36337068, 35828458' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 35951818, 36337068, 35828458' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 35951826, 36337068, 35828458' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches' : '36271505, 36298760, 36050661, 36317311, 35828631, 35828458' },
  { 'min_version' : '12.2.13', 'max_version' : '12.2.13.99999999', 'fix_patches' : '36271505, 35828631, 35828458' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  fix_date:'202404'
);
