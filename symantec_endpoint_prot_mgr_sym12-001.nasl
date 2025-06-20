#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57767);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2011-0550");
  script_bugtraq_id(48231);
  script_xref(name:"Secunia", value:"43662");

  script_name(english:"Symantec Endpoint Protection Manager TestConnection.jsp 'Msg' Parameter XSS (SYM11-009 & SYM12-001)");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager running on the
remote web server is affected by a cross-site scripting (XSS)
vulnerability due to improper sanitization of input to the 'Msg'
parameter in the TestConnection.jsp file. An unauthenticated, remote
attacker can exploit this vulnerability by convincing a user to make a
malicious request, resulting in the execution of arbitrary script code
in the user's browser session.

This version of Endpoint Protection Manager is affected by additional
XSS and XSRF vulnerabilities; however, Nessus has not tested for
these.");
  # https://cons0ul.wordpress.com/2011/08/15/sym11-09-cross-site-scripting-and-how-to-root-using-it/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e20e9bda");
  # https://support.symantec.com/en_US/article.SYMSA1227.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d0b67eb");
  # https://support.symantec.com/en_US/article.SYMSA1243.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?73f944d5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager 11 RU7 / 12.1 RU1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_detect.nasl");
  script_require_keys("www/sep_mgr");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9090);
install = get_install_from_kb(appname:'sep_mgr', port:port, exit_on_fail:TRUE);

dir = install['dir'] + '/portal';
xss = '<script>alert(/' + SCRIPT_NAME + '-' + unixtime() + '/)</script>';
qs = 'Error=true&Msg=' + xss;
expected_output = "color='red'>" + xss + "</font>";

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:'/TestConnection.jsp',
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<title>Test Connection</title>'
);

if (!exploited)
  exit(0, "The SEP Manager install at " + build_url(qs:dir + '/TestConnection.jsp', port:port) + " is not affected.");
