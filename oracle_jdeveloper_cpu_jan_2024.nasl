#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189243);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id(
    "CVE-2021-35515",
    "CVE-2021-35516",
    "CVE-2021-35517",
    "CVE-2021-36090",
    "CVE-2023-2976"
  );
  script_xref(name:"IAVA", value:"2024-A-0031");

  script_name(english:"Oracle JDeveloper Multiple Vulnerabilities (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JDeveloper installed on the remote host is missing a security patch. It is, therefore, affected by 
multiple vulnerabilities as referenced in the January 2024 CPU advisory. 
  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: Oracle JDeveloper 
    (Apache Commons Compress)). The supported version that is affected is 12.2.1.4.0. Easily exploitable 
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle JDeveloper. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently 
    repeatable crash (complete DOS) of Oracle JDeveloper. (CVE-2021-36090)

  - Vulnerability in the Oracle JDeveloper product of Oracle Fusion Middleware (component: ADF Faces (Google Guava)). 
    The supported version that is affected is 12.2.1.4.0. Easily exploitable vulnerability allows low privileged 
    attacker with logon to the infrastructure where Oracle JDeveloper executes to compromise Oracle JDeveloper. 
    Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access 
    to critical data or all Oracle JDeveloper accessible data as well as unauthorized access to critical data or 
    complete access to all Oracle JDeveloper accessible data. (CVE-2023-2976)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36090");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2976");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdeveloper");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jdeveloper_installed.nbin");
  script_require_keys("installed_sw/Oracle JDeveloper");

  exit(0);
}

include('vcf_extras_oracle.inc');

var app_info = vcf::oracle_jdev::get_app_info();

var constraints = [
  { 'min_version':'12.2.1.4', 'fixed_version':'12.2.1.4.231205', 'missing_patch':'36074941' }
];

vcf::oracle_jdev::check_version_and_report(
  app_info:app_info,
  severity:SECURITY_WARNING,
  constraints:constraints
);
