#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51200);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2010-4113");
  script_bugtraq_id(45438);
  script_xref(name:"TRA", value:"TRA-2010-05");

  script_name(english:"HP Power Manager < 4.3.2");

  script_set_attribute(attribute:"synopsis", value:
"The power management application installed on the remote host has a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of HP Power Manager is less than 4.3.2, and as
such has a buffer overflow vulnerability.  Input to the 'Login'
parameter of the login page is not properly sanitized, which can
result in a stack-based buffer overflow.

An unauthenticated, remote attacker could exploit this by sending a
specially crafted HTTP request, resulting in arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2010-05");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-10-292/");
  # http://web.archive.org/web/20130415035544/http://h20000.www2.hp.com:80/bizsupport/TechSupport/Document.jsp?objectID=c02239581
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8ecd9c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Power Manager 4.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:power_manager");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("hp_power_mgr_web_detect.nasl");
  script_require_keys("www/hp_power_mgr");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded:TRUE);
install = get_install_from_kb(appname:'hp_power_mgr', port:port, exit_on_fail:TRUE);

fix = '4.3.2';
version = install['ver'];
if (version == UNKNOWN_VER)
  exit(1, 'The version of HP PM installed on port '+port+' is unknown.');

if (ver_compare(ver:version, fix:fix) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : '+version+'
              \n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'HP PM version '+version+' is installed and thus not affected.');

