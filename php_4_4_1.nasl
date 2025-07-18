#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20111);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id(
    "CVE-2002-0229",
    "CVE-2005-2491",
    "CVE-2005-3388",
    "CVE-2005-3389",
    "CVE-2005-3390"
  );
  script_bugtraq_id(
    14620,
    15248,
    15249,
    15250
  );

  script_name(english:"PHP < 4.4.1 / 5.0.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 4.4.1 or 5.0.6.  Such versions fail to protect the
'$GLOBALS' superglobals variable from being overwritten due to
weaknesses in the file upload handling code as well as the 'extract()'
and 'import_request_variables()' functions.  Depending on the nature
of the PHP applications on the affected host, exploitation of this
issue may lead to any number of attacks, including arbitrary code
execution. 

In addition, these versions may enable an attacker to exploit an
integer overflow flaw in certain certain versions of the PCRE library,
to enable PHP's 'register_globals' setting even if explicitly disabled
in the configuration, and to launch cross-site scripting attacks
involving PHP's 'phpinfo()' function.");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_182005.77.html");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_192005.78.html");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_202005.79.html");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/release_4_4_1.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 4.4.1 / 5.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2024 Tenable Network Security, Inc.");

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
    version =~ "^4\.([0-3]\.|4\.0($|[^0-9]))" || 
    version =~ "^5\.0\.[0-5]($|[^0-9])"
)
{
 set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
 if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.4.1 / 5.0.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
