#%NASL_MIN_LEVEL 70300
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (4/30/09)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11815);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_name(english:"Horde IMP IMP_MIME_Viewer_html Class XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server is running at least one instance of IMP whose 
version number is between 3.0 and 3.2.1 inclusive.  Such versions are
vulnerable to several cross-scripting attacks whereby an attacker can 
cause a victim to unknowingly run arbitrary JavaScript code simply by 
reading an HTML message from the attacker. 

Note : Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there.  If the
installation has already been patched, consider this a false positive.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=imp&m=105940167329471&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=imp&m=105981180431599&w=2");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=imp&m=105990362513789&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IMP version 3.2.2 or later or apply patches found
in the announcements to imp/lib/MIME/Viewer/html.php.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:imp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2003-2024 George A. Theall");

  script_dependencies("global_settings.nasl", "imp_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80, embedded:TRUE);
dbg::detailed_log(lvl:2, msg:"debug: searching for MIME_Viewer_html XSS vulnerability in IMP on "+host+":"+port+".");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    dbg::detailed_log(lvl:2, msg:"debug: checking version "+ver+" under "+dir+".");

    if (ereg(pattern:"^3\.(0|1|2|2\.1)$", string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
