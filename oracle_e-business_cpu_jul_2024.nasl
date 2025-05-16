#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202705);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id(
    "CVE-2024-21128",
    "CVE-2024-21132",
    "CVE-2024-21143",
    "CVE-2024-21146",
    "CVE-2024-21148",
    "CVE-2024-21149",
    "CVE-2024-21152",
    "CVE-2024-21153",
    "CVE-2024-21167",
    "CVE-2024-21169"
  );
  script_xref(name:"IAVA", value:"2024-A-0424-S");

  script_name(english:"Oracle E-Business Suite (July 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host is affected by multiple vulnerabilities as
referenced in the July 2024 CPU advisory.

  - Vulnerability in the Oracle Trading Community product of Oracle E-Business Suite (component: Party Search
    UI). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Trading Community. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle Trading Community accessible data as well as unauthorized access to critical
    data or complete access to all Oracle Trading Community accessible data. (CVE-2024-21167)

  - Vulnerability in the Oracle Process Manufacturing Product Development product of Oracle E-Business Suite
    (component: Quality Management Specs). The supported version that is affected is 12.2.13. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    Process Manufacturing Product Development. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Oracle Process
    Manufacturing Product Development accessible data as well as unauthorized access to critical data or
    complete access to all Oracle Process Manufacturing Product Development accessible data. (CVE-2024-21153)

  - Vulnerability in the Oracle Process Manufacturing Financials product of Oracle E-Business Suite
    (component: Allocation Rules). Supported versions that are affected are 12.2.12-12.2.13. Easily
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
    Process Manufacturing Financials. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Oracle Process Manufacturing Financials
    accessible data as well as unauthorized access to critical data or complete access to all Oracle Process
    Manufacturing Financials accessible data. (CVE-2024-21152)

  - Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component:
    APIs). Supported versions that are affected are 12.2.6-12.2.13. Easily exploitable vulnerability allows
    low privileged attacker with network access via HTTP to compromise Oracle Application Object Library.
    Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in Oracle Application Object Library, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Oracle Application Object Library accessible data as well as
    unauthorized read access to a subset of Oracle Application Object Library accessible data.
    (CVE-2024-21128)

  - Vulnerability in the Oracle Purchasing product of Oracle E-Business Suite (component: Approvals).
    Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Purchasing. Successful attacks
    require human interaction from a person other than the attacker and while the vulnerability is in Oracle
    Purchasing, attacks may significantly impact additional products (scope change). Successful attacks of
    this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Purchasing
    accessible data as well as unauthorized read access to a subset of Oracle Purchasing accessible data.
    (CVE-2024-21132)

  - Vulnerability in the Oracle iStore product of Oracle E-Business Suite (component: User Management).
    Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Oracle iStore. Successful attacks of
    this vulnerability can result in unauthorized read access to a subset of Oracle iStore accessible data.
    (CVE-2024-21143)

  - Vulnerability in the Oracle Trade Management product of Oracle E-Business Suite (component: GL Accounts).
    Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows low
    privileged attacker with network access via HTTP to compromise Oracle Trade Management. Successful attacks
    of this vulnerability can result in unauthorized creation, deletion or modification access to critical
    data or all Oracle Trade Management accessible data as well as unauthorized access to critical data or
    complete access to all Oracle Trade Management accessible data. (CVE-2024-21146)

  - Vulnerability in the Oracle Applications Framework product of Oracle E-Business Suite (component:
    Personalization). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable
    vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle
    Applications Framework. Successful attacks require human interaction from a person other than the attacker
    and while the vulnerability is in Oracle Applications Framework, attacks may significantly impact
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Applications Framework accessible data as well as
    unauthorized read access to a subset of Oracle Applications Framework accessible data. (CVE-2024-21148)

  - Vulnerability in the Oracle Enterprise Asset Management product of Oracle E-Business Suite (component:
    Work Definition Issues). Supported versions that are affected are 12.2.11-12.2.13. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle Enterprise
    Asset Management. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Oracle Enterprise Asset Management accessible data as well
    as unauthorized access to critical data or complete access to all Oracle Enterprise Asset Management
    accessible data. (CVE-2024-21149)

  - Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Partners). Supported
    versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise Oracle Marketing. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle Marketing
    accessible data as well as unauthorized read access to a subset of Oracle Marketing accessible data.
    (CVE-2024-21169)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21153");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_ebusiness::get_app_info();

var constraints = [
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches':'36561740, 36594340' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches':'36561740, 36594347, 36453170' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches':'36561740, 36594351, 33405354, 36560216' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches':'36561740, 36560216, 36594391, 33405354' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches':'36561740, 36560216, 36594398, 33405354' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches':'36561740, 36560216, 36594402, 33405354' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches':'36561740, 36560216, 36594406, 33405354' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches':'36561740, 36560216, 36594411, 33405354, 36605871' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches':'36561740, 36560216, 36594416, 33405354, 36605881, 36744078' },
  { 'min_version' : '12.2.13', 'max_version' : '12.2.13.99999999', 'fix_patches':'36561740, 36560216, 36605881, 36744078, 36170989' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  fix_date:'202407'
);
