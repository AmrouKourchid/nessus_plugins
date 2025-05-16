#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233861);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2024-36469");
  script_xref(name:"IAVA", value:"2025-A-0215");

  script_name(english:"Zabbix 5.x < 5.0.46rc1 / 6.x < 6.0.38rc1 / 7.0.x < 7.0.9rc1 / 7.2.x < 7.2.3rc1 User Enumeration (ZBX-26255)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a user enumeration vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zabbix installed on the remote host affected by a user enumeration vulnerability. Execution time for an
unsuccessful login differs when using a non-existing username compared to using an existing one.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.zabbix.com/browse/ZBX-26255");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zabbix version 5.0.46rc1, 6.0.38rc1, 7.0.9rc1, 7.2.3rc1 or later");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36469");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zabbix:zabbix");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'min_version':'5.0.0', 'fixed_version':'5.0.46rc1'},
  {'min_version':'6.0.0', 'fixed_version':'6.0.38rc1'},
  {'min_version':'7.0.0', 'fixed_version':'7.0.9rc1'},
  {'min_version':'7.2', 'fixed_version':'7.2.3rc1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
