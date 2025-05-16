#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45553);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_name(english:"Apache ActiveMQ Web Console Test Pages Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is leaking information.");
  script_set_attribute(attribute:"description", value:
"The Apache ActiveMQ Web Console running on the remote host is leaking
information via its test pages. The ActiveMQ Web Console allows
unrestricted, unauthenticated access by default, and the test pages
are used for testing the environment and web framework.

One of the included test pages, 'systemProperties.jsp', displays
information about the ActiveMQ installation and the system it is
running on, which a remote attacker can use to mount further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/web-console.html");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the ActiveMQ Web Console.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on internal evaluation of the vulnerability by Tenable.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/Apache ActiveMQ");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("http.inc");
include("install_func.inc");

var app = 'Apache ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:8161);

var install = get_single_install(
  app_name : app,
  port     : port
);

var dir = install['path'];
var install_url = build_url(port:port, qs:dir);

var url = '/test/systemProperties.jsp';
var res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if ('Test Pages</title>' >< res[2] && 'java.class.version' >< res[2])
{
  # attempt to extract some information of interest
  var info = '';
  var props = make_array(
    'activemq.home', 'ActiveMQ path',
    'os.name', 'Operating system',
    'java.version','Java version',
    'os.arch', 'Architecture'
  );

  foreach var prop (keys(props))
  {
    var pattern = '<td class="label">'+prop+'</td>[ \\r\\n\\t]+<td>([^<]+)</td>';
    var match = eregmatch(string:res[2], pattern:pattern);
    if (match) info += '  ' + props[prop] + ': ' + match[1] + '\n';
  }

  if (empty_or_null(info)) info = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    line_limit  : 5,
    request     : make_list(install_url + url),
    output      : info
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

