#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189177);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2024-20907",
    "CVE-2024-20915",
    "CVE-2024-20929",
    "CVE-2024-20933",
    "CVE-2024-20934",
    "CVE-2024-20935",
    "CVE-2024-20936",
    "CVE-2024-20938",
    "CVE-2024-20939",
    "CVE-2024-20940",
    "CVE-2024-20941",
    "CVE-2024-20943",
    "CVE-2024-20944",
    "CVE-2024-20947",
    "CVE-2024-20948",
    "CVE-2024-20949",
    "CVE-2024-20950",
    "CVE-2024-20951",
    "CVE-2024-20958"
  );
  script_xref(name:"IAVA", value:"2024-A-0028-S");

  script_name(english:"Oracle E-Business Suite (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle E-Business Suite installed on the remote host are affected a vulnerability as referenced in the
January 2024 CPU advisory.

  - Vulnerability in the Oracle Application Object Library product of Oracle E-Business Suite (component: DB 
    Privileges). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Application Object 
    Library. Successful attacks of this vulnerability can result in unauthorized update, insert or delete 
    access to some of Oracle Application Object Library accessible data as well as unauthorized read access 
    to a subset of Oracle Application Object Library accessible data.(CVE-2024-20929)

  - Vulnerability in the Oracle Knowledge Management product of Oracle E-Business Suite (component: Setup, 
    Admin). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge Management. 
    Successful attacks require human interaction from a person other than the attacker and while the 
    vulnerability is in Oracle Knowledge Management, attacks may significantly impact additional products 
    (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or 
    delete access to some of Oracle Knowledge Management accessible data as well as unauthorized read access 
    to a subset of Oracle Knowledge Management accessible data. (CVE-2024-20948)

  - Vulnerability in the Oracle Customer Interaction History product of Oracle E-Business Suite (component: 
    Outcome-Result). Supported versions that are affected are 12.2.3-12.2.13. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Customer 
    Interaction History. Successful attacks require human interaction from a person other than the attacker 
    and while the vulnerability is in Oracle Customer Interaction History, attacks may significantly impact 
    additional products (scope change). Successful attacks of this vulnerability can result in unauthorized 
    update, insert or delete access to some of Oracle Customer Interaction History accessible data as well as 
    unauthorized read access to a subset of Oracle Customer Interaction History accessible data.
    (CVE-2024-20950)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_version' : '12.2.3', 'max_version' : '12.2.3.99999999', 'fix_patches' : '35967254' },
  { 'min_version' : '12.2.4', 'max_version' : '12.2.4.99999999', 'fix_patches' : '35967254, 35951833' },
  { 'min_version' : '12.2.5', 'max_version' : '12.2.5.99999999', 'fix_patches' : '35967254, 35951840, 35411549' },
  { 'min_version' : '12.2.6', 'max_version' : '12.2.6.99999999', 'fix_patches' : '35967254, 35951852, 35411549' },
  { 'min_version' : '12.2.7', 'max_version' : '12.2.7.99999999', 'fix_patches' : '35967254, 35951856, 35411549' },
  { 'min_version' : '12.2.8', 'max_version' : '12.2.8.99999999', 'fix_patches' : '35967254, 35951899, 35411549' },
  { 'min_version' : '12.2.9', 'max_version' : '12.2.9.99999999', 'fix_patches' : '35967254, 35951906, 35411549' },
  { 'min_version' : '12.2.10', 'max_version' : '12.2.10.99999999', 'fix_patches' : '35967254, 35952410, 35411549' },
  { 'min_version' : '12.2.11', 'max_version' : '12.2.11.99999999', 'fix_patches' : '35967254, 36015885, 35411549' },
  { 'min_version' : '12.2.12', 'max_version' : '12.2.12.99999999', 'fix_patches' : '35967254, 36015885, 35411549' }
];

vcf::oracle_ebusiness::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  fix_date:'202401'
);


