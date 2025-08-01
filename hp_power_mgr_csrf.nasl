#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52015);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2011-0277");
  script_bugtraq_id(46258);
  script_xref(name:"Secunia", value:"43058");

  script_name(english:"HP Power Manager Unspecified Cross-Site Request Forgery");

  script_set_attribute(attribute:"synopsis", value:
"The power management application installed on the remote host has a
cross-site request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"HP Power Manager was detected on the remote host.  All versions of
this software reportedly have an unspecified cross-site request
forgery vulnerability.  The application does not attempt to validate
user requests before performing them.  It makes no distinction between
user actions that are performed deliberately and unknowingly.

A remote attacker could exploit this by tricking a user into making a
malicious request, resulting in administrative access.");
  # http://web.archive.org/web/20111222091932/http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02711131
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d400d597");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory above for suggested workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:power_manager");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable Network Security, Inc.");

  script_dependencies("hp_power_mgr_web_detect.nasl");
  script_require_keys("www/hp_power_mgr", "Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:80, embedded:TRUE);
install = get_install_from_kb(appname:'hp_power_mgr', port:port, exit_on_fail:TRUE);
# never reached if the app was not detected

# HP has released an advisory with no patch, so we'll assume all installs are vulnerable
set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
security_warning(port);
