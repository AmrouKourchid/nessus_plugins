#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81699);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2014-5248");

  script_name(english:"MyBB < 1.6.15 Video MyCode XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MyBB application hosted on the
remote web server is prior to 1.6.15. It is, therefore, potentially
affected by a cross-site scripting vulnerability in video MyCode due
to improper validation of user-supplied input. A remote attacker can
exploit this to execute arbitrary script code within the context of
the user's browser.");
  # https://blog.mybb.com/2014/08/04/mybb-1-6-15-released-security-maintenance-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073e8110");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MyBB version 1.6.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mybb:mybb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mybb_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/MyBB", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MyBB";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
install_url = build_url(port:port, qs:install['path']);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fix = "1.6.15";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
