#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73863);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_cve_id("CVE-2014-0185");
  script_bugtraq_id(67118);

  script_name(english:"PHP 5.5.x < 5.5.12 FPM Unix Socket Insecure Permission Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is potentially
affected by a permission escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.5.x installed on the
remote host is a version prior to 5.5.12. It is, therefore,
potentially affected by a permission escalation vulnerability.

A flaw exists within the FastCGI Process Manager (FPM) when setting permissions for a Unix
socket. This could allow a remote attacker to gain elevated privileges
after gaining access to the socket.

Note that this plugin has not attempted to exploit this issue, but
instead relied only on PHP's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.5.12");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67060");
  # https://bugs.php.net/patch-display.php?bug_id=67060&patch=mode660&revision=latest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7b8dfdd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.5.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0185");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.5)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.5\.") audit(AUDIT_NOT_DETECT, "PHP version 5.5.x", port);

if (version =~ "^5\.5\.([0-9]|1[01])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.5.12\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
