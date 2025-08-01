#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135926);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2020-7067");
  script_xref(name:"IAVA", value:"2020-A-0169-S");

  script_name(english:"PHP 7.2.x < 7.2.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on the remote web server is 7.2.x prior to 
7.2.30. It is, therefore, affected by multiple vulnerabilities:

  - An out-of-bounds read error exists in urldecode() due to improper data validation checks. An attacker can
  exploit this, by inserting negative hex values to leak values that are found in the memory before the array.
  
  - A NULL byte injection vulnerability exists in shell_exec() and the backtick operator due to improper data 
  sanitization.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://bugs.php.net/79330
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95070b64");
  # http://bugs.php.net/79465
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80dcf021");
  # http://php.net/ChangeLog-7.php#7.2.30
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c83177f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7067");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.2.0alpha1', 'fixed_version':'7.2.30'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
