#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133054);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id("CVE-2019-17091", "CVE-2020-2556", "CVE-2020-2707");
  script_xref(name:"IAVA", value:"2020-A-0037-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera P6 EnterpriseProject Portfolio Management (EPPM)
installation running on the remote web server is 15.x prior to 15.2.18.8, 16.x prior to 16.2.19.2, 17.x prior to
17.12.16.1, or 18.8.x prior to 18.8.16.`, or 19.12.1.0. It is, therefore, affected by multiple vulnerabilities:

  - An authentication bypass vulnerability exists in Oracle Primavera P6 Enterprise
    Project Portfolio Management. An unauthenticated, local attack can exploit this,
    to bypass authentication and execute arbitrary actions with root privileges.
    (CVE-2020-2556)

  - A authorization bypass vulnerability exists in Primavera P6 Enterprise Project
    Portfolio Management. An authenticated local attacker can exploit this via HTTP to
    access controlled data on the network and EPPM. (CVE-2020-2707)

  - A XSS vulnerability exists in Primavera P6 Enterprise Project Portfolio due to
    vulnerability in Mojarra components, allowing Reflected XSS because a client
    window field is mishandled. (CVE-2019-17091)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) version
15.2.18.8 / 16.2.19.2 / 17.12.16.1 / 18.8.17.0 / 19.12.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2707");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-2556");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', exit_if_zero:TRUE);

port = get_http_port(default:8004);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)', port:port);

constraints = [
  { 'min_version' : '15.1.0.0', 'fixed_version' : '15.2.18.8'},
  { 'min_version' : '16.2.0.0', 'fixed_version' : '16.2.19.2'},
  { 'min_version' : '17.12.0.0', 'fixed_version' : '17.12.16.1'},
  { 'min_version' : '18.8.0.0', 'fixed_version' : '18.8.17.0'},
  { 'min_version' : '19.12.0.0', 'fixed_version' : '19.12.1.0'}
  ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
