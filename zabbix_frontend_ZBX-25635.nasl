#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213277);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id("CVE-2024-36466");
  script_xref(name:"IAVA", value:"2024-A-0836-S");

  script_name(english:"Zabbix 6.0.x < 6.0.32rc1, 6.4.x < 6.4.17rc1, 7.0.x < 7.0.1rc1 Authentication Bypass (ZBX-25635)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zabbix installed on the remote host is prior to 6.0.32rc1, 6.4.17rc1 and 7.0.1rc1. It is therefore 
affected by authentication bypass vulnerability.

  - A bug in the code allows an attacker to sign a forged zbx_session cookie, which then allows them to sign 
    in with admin permissions. (CVE-2024-36466)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-25635");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 6.0.32rc1, 6.4.17rc1, 7.0.1rc1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zabbix_frontend_detect.nasl");
  script_require_keys("installed_sw/zabbix");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'zabbix';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:80);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version':'6.0.0', 'fixed_version':'6.0.32rc1'},
  {'min_version':'6.4.0', 'fixed_version':'6.4.17rc1'},
  {'min_version':'7.0.0', 'fixed_version':'7.0.1rc1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
