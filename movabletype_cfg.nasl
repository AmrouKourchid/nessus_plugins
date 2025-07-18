#%NASL_MIN_LEVEL 70300
#
# This script was written by Rich Walchuck (rich.walchuck at gmail.com)
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Reformatted description and added dependency (7/7/2009)
# - Revised plugin title (3/25/2009)
# - Added misc_func.inc and audit.inc

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16170);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_name(english:"Movable Type mt.cfg Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is disclosing sensitive
information.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Movable Type.  The file 'mt.cfg' is
publicly accessible, and contains information that should not be exposed.");
  script_set_attribute(attribute:"solution", value:
"Configure your web server not to serve .cfg files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sixapart:movable_type");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2024 Rich Walchuck");

  script_dependencies("movabletype_detect.nasl");
  script_require_keys("www/movabletype", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:TRUE);

install = get_kb_item_or_exit("www/" + port + "/movabletype");

match = eregmatch(string:install, pattern:'^.+ under (/.*)$');
if (isnull(match)) exit(1, "Error retrieving dir of Movable Type installation from the KB.");

mt_dir = match[1];
url = mt_dir + '/mt.cfg';
install_url = build_url(qs:mt_dir, port:port);

if (is_cgi_installed_ka(item:url, port:port))
{
  if (report_verbosity > 0)
  {
    report = 'Nessus was able to verify the issue exists using the following URL :' +
      '\n' +
      '\n' + install_url + "/mt.cfg" +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Movable Type", install_url);
