#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24906);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2006-4625",
    "CVE-2007-0905",
    "CVE-2007-0906",
    "CVE-2007-0907",
    "CVE-2007-0908",
    "CVE-2007-0909",
    "CVE-2007-0910",
    "CVE-2007-0988",
    "CVE-2007-1286",
    "CVE-2007-1376",
    "CVE-2007-1378",
    "CVE-2007-1379",
    "CVE-2007-1380",
    "CVE-2007-1700",
    "CVE-2007-1701",
    "CVE-2007-1777",
    "CVE-2007-1825",
    "CVE-2007-1835",
    "CVE-2007-1884",
    "CVE-2007-1885",
    "CVE-2007-1886",
    "CVE-2007-1887",
    "CVE-2007-1890"
  );
  script_bugtraq_id(
    22496,
    22805,
    22806,
    22833,
    22862,
    23119,
    23120,
    23169,
    23219,
    23233,
    23234,
    23235,
    23236
  );

  script_name(english:"PHP < 4.4.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.5.  Such versions may be affected by several
issues, including buffer overflows, format string vulnerabilities,
arbitrary code execution, 'safe_mode' and 'open_basedir' bypasses, and
clobbering of super-globals.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/4_4_5.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'PHP 4 unserialize() ZVAL Reference Counter Overflow (Cookie)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2024 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^3\." ||
    version =~ "^4\.[0-3]\." ||
    version =~ "^4\.4\.[0-4]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
