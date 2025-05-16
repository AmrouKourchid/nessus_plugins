#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235453);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2023-26464", "CVE-2024-25710");
  script_xref(name:"IAVA", value:"2025-A-0268");

  script_name(english:"Oracle JDeveloper DoS (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is missing a security patch. It is, therefore, affected 
by denial of service vulnerability as referenced in the April 2025 CPU advisory. 

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: Generic (Apache 
    Log4j)). The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows 
    unauthenticated attacker with network access via HTTP to compromise Oracle JDeveloper. Successful attacks 
    of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Oracle JDeveloper. (CVE-2023-26464)

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: Generic (Apache 
    Commons Compress)). The supported version that is affected is 12.2.1.4.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with logon to the infrastructure where Oracle JDeveloper 
    executes to compromise Oracle JDeveloper. Successful attacks require human interaction from a person 
    other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle JDeveloper. (CVE-2024-25710)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26464");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'12.2.1.4', 'fixed_version':'12.2.1.4.250416', 'missing_patch':'37836334' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_HOLE,
  constraints:constraints
);
