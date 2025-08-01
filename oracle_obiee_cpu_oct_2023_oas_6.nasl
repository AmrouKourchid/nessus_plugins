#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2020-11988",
    "CVE-2023-22082",
    "CVE-2023-22109",
    "CVE-2023-22946",
    "CVE-2022-26612",
    "CVE-2023-30535",
    "CVE-2023-30861",
    "CVE-2022-33980",
    "CVE-2023-34462",
    "CVE-2022-41409",
    "CVE-2021-43045"
  );
  script_xref(name:"IAVA", value:"2023-A-0556");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (OAS 6.4) (October 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Business Intelligence Enterprise Edition (OAS) 6.4.0.0.0 installed on the remote
host is affected by multiple vulnerabilities as referenced in the October 2023 CPU advisory, including the
following:

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
  (component: Analytics Server (Apache Spark)). The supported version that is affected is 6.4.0.0.0. Easily
  exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle
  Business Intelligence Enterprise Edition. While the vulnerability is in Oracle Business Intelligence
  Enterprise Edition, attacks may significantly impact additional products (scope change). Successful attacks
  of this vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition.
  (CVE-2023-22946)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
  (component: Analytics Server (Apache Hadoop)). The supported version that is affected is 6.4.0.0.0. Easily
  exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle
  Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in takeover of
  Oracle Business Intelligence Enterprise Edition. (CVE-2022-26612)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics
  (component: Content Storage Service (Apache Commons Configuration)). Supported versions that are affected
  are 6.4.0.0.0 and 7.0.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network
  access via HTTP to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this
  vulnerability can result in takeover of Oracle Business Intelligence Enterprise Edition. (CVE-2022-33980)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33980");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-22946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_analytics_server_installed.nbin");
  script_require_keys("installed_sw/Oracle Analytics Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Analytics Server');

# based on Oracle CPU data
var constraints = [
  {'min_version': '6.4.0.0.0', 'fixed_version': '6.4.0.0.230929', 'fixed_display': '6.4.0.0.230929 patch: 35860763'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);