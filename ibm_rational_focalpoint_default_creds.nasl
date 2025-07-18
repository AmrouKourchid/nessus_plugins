#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72860);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_name(english:"IBM Rational Focal Point Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is using a known set
of default credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote IBM Rational Focal Point install
using a default set of known credentials.  A remote attacker using these
credentials can gain administrative access to the web application.");
  script_set_attribute(attribute:"solution", value:
"Change the password for the 'admin' user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_focal_point");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("ibm_rational_focalpoint_login_detect.nbin");
  script_require_keys("www/ibm_rational_focal_point");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 9080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:9080);

install = get_install_from_kb(
  appname      : "ibm_rational_focal_point",
  port         : port,
  exit_on_fail : TRUE
);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

dir = install['dir'];
url = dir + '/fp/servlet/Login';

postdata =
  'username=admin&' +
  'password=focalpoint&' +
  'FPaction=login';

res = http_send_recv3(
  port            : port,
  method          : 'POST',
  item            : url,
  data            : postdata,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE
);

if ('file=/login/loginOk.jsp' >< res[1])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : admin\n' +
      '  Password : focalpoint';

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "IBM Rational Focalpoint", build_url(qs:dir, port:port));
