#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90026);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2016-0734");

  script_name(english:"Apache ActiveMQ Web Console Missing X-Frame-Options Clickjacking");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
clickjacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache ActiveMQ running on the remote host is affected
by a clickjacking vulnerability in the web-based administration
console due to not setting the X-Frame-Options header in HTTP
responses. A remote attacker can exploit this to trick a user into
executing administrative tasks.

Note that this vulnerability was partially fixed in 5.11.4 and 5.12.3
by setting the X-Frame-Options header for Servlets and JSPs but not
static content. Therefore, the fix for these versions is incomplete,
and it is recommended that users upgrade to 5.13.2 or later.");
  # http://activemq.apache.org/security-advisories.data/CVE-2016-0734-announcement.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7cdf2a0");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-6170");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AMQ-6113");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache ActiveMQ version 5.13.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0734");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  port     : port,
  exit_if_unknown_ver : FALSE
);

var dir = install['path'];
var install_url = build_url(port:port, qs:dir);

var headers = NULL;

# Look at cache first
var res = http_get_cache(port:port, item:"/");
if (!empty_or_null(res))
{
  res = split(res, sep:'\r\n\r\n\r\n', keep:FALSE);
  headers = res[0];
}
else
{
  res = http_send_recv3(
    method : "GET",
    item   : "/",
    port   : port,
    exit_on_fail : TRUE
  );
  
  headers = res[1];
}

var pat = "^X-Frame-Options: (DENY|SAMEORIGIN|ALLOW-FROM)";
if (egrep(pattern:pat, string:headers, icase:TRUE))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
  
var fix = '5.13.2';
var report = NULL;

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify the issue exists by requesting the following '+
    '\n' + 'URL and examining the response header :' +
    '\n' +
    '\n' + install_url +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
     '\n' + 'The remote ActiveMQ server produced the following response header :' +
     '\n' +
     '\n' + chomp(headers) +
     '\n';
  }
}

security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xsrf:TRUE);
