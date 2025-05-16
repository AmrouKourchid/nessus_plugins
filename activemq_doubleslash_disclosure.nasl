#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(45623);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2010-1587");
  script_bugtraq_id(39636);

  script_name(english:"Apache ActiveMQ Double Slash Request Source Code Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ hosted on the remote web server is affected by
a source code disclosure vulnerability in the Jetty ResourceHandler
when handling requests to a JSP file with additional leading slashes.
A remote attacker can exploit this to disclose the source code of
pages, which may contain passwords and other sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/510896/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-2700");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to the latest ActiveMQ 5.4 snapshot or apply the
workaround described in the bug report.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1587");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache ActiveMQ Source Code Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (thorough_tests)
{
  var urls = make_list(
    dir + '/index.jsp',
    dir + '/queues.jsp',
    dir + '/topics.jsp',
    '/camel/WEB-INF/decorators/main.jsp'
  );
}
else
{
  urls = make_list(
    dir + '/index.jsp'
  );
}

var url, exploit, res, res2,report;

# Try to exploit the issue.
foreach url (urls)
{
  exploit = '/' + url;
  res = http_send_recv3(method:"GET", item:exploit, port:port, exit_on_fail:TRUE);
  # If it looks like source...
  if (
    "Content-Type: text/plain" >< res[1] &&
    res[2] && "<%" >< res[2] && "%>" >< res[2]
  )
  {
    res2 = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
    if (res2[2] && "<%" >!< res2[2] && "%>" >!< res2[2])
    {
      if (report_verbosity > 0)
      {
        report = '\n' +
          'Nessus was able to verify the vulnerability using the following URL :\n' +
          '\n' +
          '  ' + build_url(port:port, qs:exploit) + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));
