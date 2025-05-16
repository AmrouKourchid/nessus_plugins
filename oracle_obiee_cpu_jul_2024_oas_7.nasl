#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202907);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/23");

  script_cve_id(
    "CVE-2022-0239",
    "CVE-2022-21797",
    "CVE-2022-40152",
    "CVE-2023-1370",
    "CVE-2023-49083",
    "CVE-2024-0727",
    "CVE-2024-21139"
  );

  script_name(english:"Oracle Business Intelligence Enterprise Edition (OAS 7.0) (July 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Enterprise Edition (OAS) 7.0.0.0 installed on the remote
host is affected by multiple vulnerabilities as referenced in the July 2024 CPU advisory, including the
following:

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (Stanford CoreNLP)). The supported version that is affected is 7.0.0.0.0. 
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can 
    result in takeover of Oracle Business Intelligence Enterprise Edition. (CVE-2022-0239)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (OpenSSL)). Supported versions that are affected are 7.0.0.0.0, 7.6.0.0.0 
    and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with logon to the 
    infrastructure where Oracle Business Intelligence Enterprise Edition executes to compromise Oracle 
    Business Intelligence Enterprise Edition. Successful attacks require human interaction from a person 
    other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to 
    cause a hang or frequently repeatable crash (complete DOS) of Oracle Business Intelligence Enterprise 
    Edition. (CVE-2024-0727)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Web Answers). Supported versions that are affected are 7.0.0.0.0, 7.6.0.0.0 and 
    12.2.1.4.0. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP 
    to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks require human 
    interaction from a person other than the attacker and while the vulnerability is in Oracle Business 
    Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). 
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to 
    some of Oracle Business Intelligence Enterprise Edition accessible data as well as unauthorized read 
    access to a subset of Oracle Business Intelligence Enterprise Edition accessible data. (CVE-2024-21139)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0239");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21797");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_analytics_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Analytics Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Analytics Server');

# based on Oracle CPU data
var constraints = [
  {'min_version': '7.0.0.0.0', 'fixed_version': '7.0.0.0.240702', 'fixed_display': '7.0.0.0.240702 patch: 36797748'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);