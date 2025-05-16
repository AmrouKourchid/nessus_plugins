 #%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200162);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-4577", "CVE-2024-5458", "CVE-2024-5585");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/03");
  script_xref(name:"IAVA", value:"2024-A-0330-S");

  script_name(english:"PHP 8.2.x < 8.2.20 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 8.2.20. It is, therefore, affected by multiple
vulnerabilities as referenced in the Version 8.2.20 advisory.

  - In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-
    CGI on Windows, if the system is set up to use certain code pages, Windows may use Best-Fit behavior to
    replace characters in command line given to Win32 API functions. PHP CGI module may misinterpret those
    characters as PHP options, which may allow a malicious user to pass options to PHP binary being run, and
    thus reveal the source code of scripts, run arbitrary PHP code on the server, etc. (CVE-2024-4577)

  - In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, due to a code logic error,
    filtering functions such as filter_var when validating URLs (FILTER_VALIDATE_URL) for certain types of
    URLs the function will result in invalid user information (username + password part of URLs) being treated
    as valid user information. This may lead to the downstream code accepting invalid URLs as valid and
    parsing them incorrectly. (CVE-2024-5458)

  - In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, the fix for CVE-2024-1874
    does not work if the command name includes trailing spaces. Original issue: when using proc_open() command
    with array syntax, due to insufficient escaping, if the arguments of the executed command are controlled
    by a malicious user, the user can supply arguments that would execute arbitrary commands in Windows shell.
    (CVE-2024-5585)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-8.php#8.2.20");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 8.2.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4577");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80, php:TRUE);
var app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

var backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

var constraints = [
  { 'min_version' : '8.2.0alpha1', 'fixed_version' : '8.2.20' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
