#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85218);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");
  script_bugtraq_id(55253);

  script_name(english:"Atlassian JIRA < 5.0.7 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is prior to 5.0.7. It
is, therefore, potentially affected by a privilege escalation
vulnerability. A remote attacker, using a crafted URL, can exploit
this to bypass administrator-only authorization controls, thus gaining
the ability to execute a large number of possible administrative
actions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/jira/jira-security-advisory-2012-08-28-297667738.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92bd5816");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA 5.0.7 or later, or apply the vendor-supplied
patch that applies to your installed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];

url = build_url(port:port, qs:dir);

# All versions prior to 5.0.7 are affected. 
# Ref: https://jira.atlassian.com/browse/JRA-29403
fix = "5.0.7";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
