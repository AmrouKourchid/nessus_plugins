#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87053);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");
  script_xref(name:"EDB-ID", value:"38339");

  script_name(english:"Centreon 2.6.x < 2.6.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Centreon application hosted on
the remote web server is version 2.6.x prior to 2.6.5. It is,
therefore, affected by multiple vulnerabilities :

  - A cross-site request forgery (XSRF) vulnerability exists
    in the main.php script. A remote attacker can exploit
    this to perform administrative actions by convincing a
    user to follow a link to a malicious website.

  - A flaw exists in the main.php script due to improper
    sanitization of user-supplied input to the POST
    'persistent' parameter. An authenticated, remote
    attacker can exploit this to execute arbitrary shell
    commands.

  - A cross-site scripting vulnerability exists in the
    main.php script due to improper sanitization of
    user-supplied input to the 'img_comment' POST parameter.
    An authenticated, remote attacker can exploit this, via
    a crafted request, to execute arbitrary script code in a
    user's browser session.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  # https://packetstormsecurity.com/files/133758/Centreon-2.6.1-Persistent-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9f1c3d2");
  # https://packetstormsecurity.com/files/133751/Centreon-2.6.1-Add-Administrator-Cross-Site-Request-Forgery.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7aec14c");
  # https://packetstormsecurity.com/files/133754/Centreon-2.6.1-Command-Injection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cebce424");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Centreon version 2.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if(version =~ "^2\.6\." && ver_compare(ver:version, fix:"2.6.5", strict:FALSE) < 0)
{
  set_kb_item(name: 'www/' + port + '/XSS', value: TRUE);
  set_kb_item(name: 'www/' + port + '/XSRF', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 2.6.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
