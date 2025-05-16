#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189184);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-2976", "CVE-2023-5072", "CVE-2023-42503");
  script_xref(name:"IAVA", value:"2024-A-0026-S");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (January 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Primavera P6 Enterprise Project Portfolio Management installed on the remote host are affected by
vulnerabilities as referenced in the January 2024 CPU advisory.

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web (Google Guava)). Supported versions that are affected are
    19.12.0-19.12.22, 20.12.0-20.12.20, 21.12.0-21.12.17 and 22.12.0-22.12.10. Easily exploitable
    vulnerability allows low privileged attacker with logon to the infrastructure where Primavera P6
    Enterprise Project Portfolio Management executes to compromise Primavera P6 Enterprise Project Portfolio
    Management. Successful attacks of this vulnerability can result in unauthorized creation, deletion or
    modification access to critical data or all Primavera P6 Enterprise Project Portfolio Management
    accessible data as well as unauthorized access to critical data or complete access to all Primavera P6
    Enterprise Project Portfolio Management accessible data. (CVE-2023-2976)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web (Apache Commons Compress)). Supported versions that are affected are
    19.12.0-19.12.22, 20.12.0-20.12.20, 21.12.0-21.12.17 and 22.12.0-22.12.10. Easily exploitable
    vulnerability allows low privileged attacker with logon to the infrastructure where Primavera P6
    Enterprise Project Portfolio Management executes to compromise Primavera P6 Enterprise Project Portfolio
    Management. Successful attacks require human interaction from a person other than the attacker. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of Primavera P6 Enterprise Project Portfolio Management. (CVE-2023-42503)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web (JSON-java)). Supported versions that are affected are 19.12.0-19.12.22,
    20.12.0-20.12.20, 21.12.0-21.12.17 and 22.12.0-22.12.10. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Primavera P6 Enterprise Project
    Portfolio Management. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a hang or frequently repeatable crash (complete DOS) of Primavera P6 Enterprise Project Portfolio
    Management. (CVE-2023-5072)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2024.html#AppendixPVA");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2976");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include('vcf.inc');
include('http.inc');

get_install_count(app_name:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', exit_if_zero:TRUE);

var port = get_http_port(default:8004);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

var app_info = vcf::get_app_info(app:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', port:port);

var constraints = [
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.22.1' },
  { 'min_version' : '20.12.0.0', 'fixed_version' : '20.12.21.0' },
  { 'min_version' : '21.12.0.0', 'fixed_version' : '21.12.18.0' },
  { 'min_version' : '22.12.0.0', 'fixed_version' : '22.12.11.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
