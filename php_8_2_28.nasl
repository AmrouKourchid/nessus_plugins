#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232707);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2025-1217",
    "CVE-2025-1219",
    "CVE-2025-1734",
    "CVE-2025-1736",
    "CVE-2025-1861"
  );
  script_xref(name:"IAVA", value:"2025-A-0183");

  script_name(english:"PHP 8.2.x < 8.2.28 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of PHP installed on the remote host is prior to 8.2.28. It is, therefore, affected by multiple
vulnerabilities as referenced in the Version 8.2.28 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-8.php#8.2.28");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-52jp-hrpf-2jff");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-hgf5-96fm-v528");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-p3x9-6h7p-cgfc");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-pcmh-g36c-qc44");
  script_set_attribute(attribute:"see_also", value:"https://github.com/php/php-src/security/advisories/GHSA-v8xr-gpvj-cx9g");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 8.2.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '8.2.0alpha1', 'fixed_version' : '8.2.28' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
