#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29834);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2007-6617", "CVE-2007-6618", "CVE-2007-6619");
  script_bugtraq_id(27094, 27095);

  script_name(english:"Atlassian JIRA 500page.jsp XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Atlassian JIRA installation hosted on the remote web server is
affected by a cross-site scripting (XSS) vulnerability due to a
failure to properly sanitize user-supplied error messages before being
passed to the 500page.jsp script. A remote attacker, using a crafted
URL, can exploit this to execute arbitrary code in a user's browser.

Note that the application is also reportedly affected by multiple
security bypass vulnerabilities; however, Nessus has not tested for
these. Refer to the advisory for more information.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-13999");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-14086");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-14105");
  # https://confluence.atlassian.com/jira/jira-security-advisory-2007-12-24-116949034.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea522a47");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA 3.12.1 or later. Alternatively, apply the
appropriate patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2024 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

# Try to exploit the XSS issue.
xss = "<BODY onload=alert('" + SCRIPT_NAME + "')>";
command = SCRIPT_NAME + "'" + xss;

url = '/secure/CreateIssue!'+urlencode(str:command)+'.jspa';
w = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);
res = w[2];

if (
  # it's Atlassian JIRA and ...
  "com.atlassian.jira." >< res &&
  # the output complains about our choice of command
  "No command '" + command + "' in action" >< res
)
{
  output = strstr(res, "No command");
  if (empty_or_null(output)) output = chomp(res);

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE, # Sets XSS kb item
    request    : make_list(build_url(qs:dir + url, port:port)),
    output     : chomp(output)
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
