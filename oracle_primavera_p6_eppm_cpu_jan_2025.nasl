#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214528);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2025-21526", "CVE-2025-21528", "CVE-2025-21558");
  script_xref(name:"IAVA", value:"2025-A-0044");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (January 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Primavera P6 Enterprise Project Portfolio Management installed on the remote host are affected by
multiple vulnerabilities as referenced in the January 2025 CPU advisory.

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 20.12.1.0-20.12.21.5,
    21.12.1.0-21.12.20.0, 22.12.1.0-22.12.16.0 and 23.12.1.0-23.12.10.0. Easily exploitable vulnerability
    allows low privileged attacker with network access via HTTP to compromise Primavera P6 Enterprise Project
    Portfolio Management. Successful attacks require human interaction from a person other than the attacker
    and while the vulnerability is in Primavera P6 Enterprise Project Portfolio Management, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access to some of Primavera P6 Enterprise Project
    Portfolio Management accessible data as well as unauthorized read access to a subset of Primavera P6
    Enterprise Project Portfolio Management accessible data. (CVE-2025-21526)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 20.12.1.0-20.12.21.5,
    21.12.1.0-21.12.20.0, 22.12.1.0-22.12.16.0 and 23.12.1.0-23.12.10.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Primavera P6 Enterprise Project
    Portfolio Management. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Primavera P6 Enterprise Project Portfolio Management accessible data. (CVE-2025-21528)

  - Vulnerability in the Primavera P6 Enterprise Project Portfolio Management product of Oracle Construction
    and Engineering (component: Web Access). Supported versions that are affected are 20.12.1.0-20.12.21.5,
    21.12.1.0-21.12.20.0 and 22.12.1.0. Easily exploitable vulnerability allows low privileged attacker with
    network access via HTTP to compromise Primavera P6 Enterprise Project Portfolio Management. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Primavera P6 Enterprise Project Portfolio Management, attacks may significantly impact additional products
    (scope change). Successful attacks of this vulnerability can result in unauthorized update, insert or
    delete access to some of Primavera P6 Enterprise Project Portfolio Management accessible data as well as
    unauthorized read access to a subset of Primavera P6 Enterprise Project Portfolio Management accessible
    data. (CVE-2025-21558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2025 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21558");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:primavera_p6_enterprise_project_portfolio_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '20.12.1.0', 'fixed_version' : '20.12.21.6' },
  { 'min_version' : '21.12.1.0', 'fixed_version' : '21.12.21.0' },
  { 'min_version' : '22.12.1.0', 'fixed_version' : '22.12.17.0' },
  { 'min_version' : '23.12.1.0', 'fixed_version' : '23.12.11.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
