#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211670);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-8929",
    "CVE-2024-8932",
    "CVE-2024-11233",
    "CVE-2024-11234",
    "CVE-2024-11236"
  );
  script_xref(name:"IAVA", value:"2024-A-0763-S");

  script_name(english:"PHP 8.3.x < 8.3.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 8.3.14. It is, therefore, affected by multiple
vulnerabilities as referenced in the Version 8.3.14 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-8.php#8.3.14");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-c5f2-jwm7-mmq2");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-g665-fm4p-vhff");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-h35g-vwh6-m678");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-r977-prxv-hc43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 8.3.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

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
  { 'min_version' : '8.3.0alpha1', 'fixed_version' : '8.3.14' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
