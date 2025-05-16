#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207821);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-8925",
    "CVE-2024-8926",
    "CVE-2024-8927",
    "CVE-2024-9026"
  );
  script_xref(name:"IAVA", value:"2024-A-0609-S");

  script_name(english:"PHP 8.3.x < 8.3.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 8.3.12. It is, therefore, affected by multiple
vulnerabilities as referenced in the Version 8.3.12 advisory.

  - In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when using a certain non-
    standard configurations of Windows codepages, the fixes for CVE-2024-4577
    https://github.com/advisories/GHSA-vxpp-6299-mxw3 may still be bypassed and the same command injection
    related to Windows Best Fit codepage behavior can be achieved. This may allow a malicious user to pass
    options to PHP binary being run, and thus reveal the source code of scripts, run arbitrary PHP code on the
    server, etc. (CVE-2024-8926)

  - In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, erroneous parsing of
    multipart form data contained in an HTTP POST request could lead to legitimate data not being processed.
    This could lead to malicious attacker able to control part of the submitted data being able to exclude
    portion of other data, potentially leading to erroneous application behavior. (CVE-2024-8925)

  - In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, HTTP_REDIRECT_STATUS
    variable is used to check whether or not CGI binary is being run by the HTTP server. However, in certain
    scenarios, the content of this variable can be controlled by the request submitter via HTTP headers, which
    can lead to cgi.force_redirect option not being correctly applied. In certain configurations this may lead
    to arbitrary file inclusion in PHP. (CVE-2024-8927)

  - In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when using PHP-FPM SAPI and
    it is configured to catch workers output through catch_workers_output = yes, it may be possible to pollute
    the final log or remove up to 4 characters from the log messages by manipulating log message content.
    Additionally, if PHP-FPM is configured to use syslog output, it may be possible to further remove log data
    using the same vulnerability. (CVE-2024-9026)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-8.php#8.3.12");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-865w-9rf3-2wh5");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-94p6-54jq-9mwp");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-9pqp-7h25-4f32");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-p99j-rfp4-xqvq");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 8.3.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8926");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.3.0alpha1', 'fixed_version' : '8.3.12' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
