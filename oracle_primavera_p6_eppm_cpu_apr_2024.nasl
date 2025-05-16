#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-21095");
  script_xref(name:"IAVA", value:"2024-A-0234-S");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (April 2024 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera P6 Enterprise Project Portfolio Management installed on the remote host are affected by a
vulnerability as referenced in the April 2024 CPU advisory.

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 19.12.0-19.12.22,
    20.12.0-20.12.21, 21.12.0-21.12.18, 22.12.0-22.12.12 and 23.12.0-23.12.2. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Primavera P6 Enterprise Project
    Portfolio Management. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Primavera P6 Enterprise Project Portfolio Management accessible
    data as well as unauthorized update, insert or delete access to some of Primavera P6 Enterprise Project
    Portfolio Management accessible data. (CVE-2024-21095)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2024csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2024.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2024 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21095");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

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
  { 'min_version' : '19.12.0', 'fixed_version' : '19.12.22.3', 'fixed_display' : 'Upgrade to 19.12.22.3 with Patch 36497985' },
  { 'min_version' : '20.12.0', 'fixed_version' : '20.12.21.2', 'fixed_display' : 'Upgrade to 20.12.21.2 with Patch 36497965' }, 
  { 'min_version' : '21.12.0', 'fixed_version' : '21.12.19', 'fixed_display' : 'Upgrade to 21.12.19 with Patch 36406394' }, 
  { 'min_version' : '22.12.0', 'fixed_version' : '22.12.13', 'fixed_display' : 'Upgrade to 22.12.13 with Patch 36305099' }, 
  { 'min_version' : '23.12.0', 'fixed_version' : '23.12.4' , 'fixed_display' : 'Upgrade to 23.12.4 with Patch 36484331' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
