#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15639);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/06");

  script_cve_id("CVE-2004-1424", "CVE-2004-1425", "CVE-2004-2232");
  script_bugtraq_id(11608, 11691, 12120);

  script_name(english:"Moodle < 1.4.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Moodle suite that is prior
to version 1.4.3. It is, therefore, affected by a SQL injection
vulnerability in the 'glossary' module due to a lack of user input
sanitization.

In addition, Moodle has also been reported to be affected by a
directory traversal and a cross-site scripting flaw. However, Nessus
has not explicitly tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Dec/423");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2004/Dec/459");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Moodle 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:moodle:moodle");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2024 Tenable Network Security, Inc.");

  script_dependencies("moodle_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/Moodle");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Moodle";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

if (version =~ "^(0\..*|1\.([0-4][^0-9]?|[0-4]\.[012][^0-9]?))$")
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
