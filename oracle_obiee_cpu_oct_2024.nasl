#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210336);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2023-0401", "CVE-2023-38545", "CVE-2024-38999");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (October 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Enterprise Edition 12.2.1.4 installed on the remote host is affected by 
multiple vulnerabilities as referenced in the October 2024 CPU advisory, including the following:

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Installation, BI Platform Security (OpenSSL)). Supported versions that are affected are 
    7.6.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network 
    access via TLS to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this 
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Oracle Business Intelligence Enterprise Edition. (CVE-2023-0401)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (curl)). Supported versions that are affected are 7.0.0.0.0, 7.6.0.0.0 
    and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    SOCKS5 to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this 
    vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. (CVE-2023-38545)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: BI Platform Security, Analytics Web Answers (RequireJS)). Supported versions that are 
    affected are 7.0.0.0.0, 7.6.0.0.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated 
    attacker with network access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. 
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete 
    access to all Oracle Business Intelligence Enterprise Edition accessible data as well as unauthorized 
    update, insert or delete access to some of Oracle Business Intelligence Enterprise Edition accessible 
    data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Business 
    Intelligence Enterprise Edition. (CVE-2024-38999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38545");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_business_intelligence_enterprise_edition_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Enterprise Edition");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Enterprise Edition');

# based on Oracle CPU data
var constraints = [
  {'min_version': '12.2.1.4', 'fixed_version': '12.2.1.4.240924', 'fixed_display': '12.2.1.4.240924 patch: 37093983'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);