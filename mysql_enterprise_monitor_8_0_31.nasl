##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163292);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2020-26237", "CVE-2021-31805");
  script_xref(name:"IAVA", value:"2022-A-0291-S");

  script_name(english:"Oracle MySQL Enterprise Monitor (July 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the July 2022 CPU advisory. 
  
  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (highlight.js)). Supported versions that are affected are 8.0.30 and prior. A malicious HTML code block can be 
    crafted that will result in prototype pollution of the base object's prototype during highlighting. 
    The pollution should just be harmless data but this can cause problems for applications not expecting these 
    properties to exist and can result in strange behavior or application crashes, i.e. a potential DOS vector. 
    (CVE-2020-26237)
  
  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Apache Struts)). Supported versions that are affected are 8.0.30 and prior. some tag attributes could perform a 
    double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL 
    evaluation on untrusted user input can lead to a Remote Code Execution and security degradation. (CVE-2021-31805)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.31' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
