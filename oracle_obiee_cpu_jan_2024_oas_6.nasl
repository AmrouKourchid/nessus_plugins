#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189734);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id(
    "CVE-2021-33813",
    "CVE-2022-25647",
    "CVE-2022-31160",
    "CVE-2022-3510",
    "CVE-2022-4304",
    "CVE-2022-44729",
    "CVE-2022-46751",
    "CVE-2023-5072",
    "CVE-2023-39410",
    "CVE-2023-23931",
    "CVE-2024-20904"
  );
  script_xref(name:"IAVA", value:"2024-A-0031");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (OAS 6.4) (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Enterprise Edition (OAS) 6.4.0.0.0 installed on the remote
host is affected by multiple vulnerabilities as referenced in the January 2024 CPU advisory, including the
following:

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (Apache Solr)). The supported version that is affected is 6.4.0.0.0. 
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can 
    result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of Oracle 
    Business Intelligence Enterprise Edition. (CVE-2021-33813)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Visual Analyzer (Apache Ivy)). The supported version that is affected is 6.4.0.0.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise 
    Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in 
    unauthorized access to critical data or complete access to all Oracle Business Intelligence Enterprise 
    Edition accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of 
    Oracle Business Intelligence Enterprise Edition. (CVE-2022-46751)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Pod Admin). Supported versions that are affected are 6.4.0.0.0 and 12.2.1.4.0. Easily 
    exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise 
    Oracle Business Intelligence Enterprise Edition. While the vulnerability is in Oracle Business 
    Intelligence Enterprise Edition, attacks may significantly impact additional products (scope change). 
    Successful attacks of this vulnerability can result in unauthorized read access to a subset of Oracle 
    Business Intelligence Enterprise Edition accessible data. (CVE-2024-20904)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25647");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-46751");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  {'min_version': '6.4.0.0.0', 'fixed_version': '6.4.0.0.240110', 'fixed_display': '6.4.0.0.240110 patch: 36174509'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_WARNING);