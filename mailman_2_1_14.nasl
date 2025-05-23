#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54579);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2010-3089");
  script_bugtraq_id(43187);

  script_name(english:"Mailman < 2.1.14 Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has multiple cross-site
scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Mailman
installation running on the remote host has multiple cross-site
scripting vulnerabilities.  These vulnerabilities can reportedly only
be exploited by a list owner.

A malicious list owner could exploit these issues to execute arbitrary
script code in another user's browser.");
  # https://mail.python.org/pipermail/mailman-announce/2010-September/000150.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2a13ff6");
  # https://mail.python.org/pipermail/mailman-announce/2010-September/000151.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9716425e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mailman 2.1.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

  script_dependencies("mailman_detect.nasl");
  script_require_keys("www/Mailman", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:80);
install = get_install_from_kb(appname:'Mailman', port:port, exit_on_fail:TRUE);
ver = install['ver'];
install_url = build_url(qs:install['dir'], port:port);

if (ver == UNKNOWN_VER)
  exit(1, 'Unable to obtain version of Mailman at ' + install_url);

if (
  ver =~ "^[01]\." ||
  ver =~ "^2\.0" ||
  ver =~ "^2\.1\.[0-9]([^0-9]|$)" ||
  ver =~ "^2\.1\.1[0-3]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 2.1.14\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, 'The Mailman '+ver+' install at '+install_url+' is not affected.');
