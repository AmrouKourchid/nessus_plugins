#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73619);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_name(english:"Atmail Webmail < 6.3.5 Multiple XSS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Atmail Webmail install on the remote
host is a version prior to 6.3.5. It is, therefore, potentially
affected by the following vulnerabilities :

  - An input validation error exists related to log search
    functionality and the 'range' and 'index' parameters.

  - An input validation error exists in the script
    'index.php/admin/users/create' related to the
    'UserFirstName' and 'UserLastName' parameters.

  - An input validation error exists in the script
    'index.php/admin/users/update' related to the
    'UserFirstName' and 'UserLastName' parameters.");
  script_set_attribute(attribute:"see_also", value:"https://help.atmail.com/hc/en-us/categories/200214454-Changelog");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id?1026486");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atmail Webmail 6.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atmail:atmail");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("atmail_webmail_detect.nasl");
  script_require_keys("www/atmail_webmail");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
install = get_install_from_kb(appname:'atmail_webmail', port:port, exit_on_fail:TRUE);

dir = install['dir'];
display_version = install['ver'];
# Get normalized version for check
kb_dir = str_replace(string:dir, find:"/", replace:"\");
version = get_kb_item_or_exit('www/'+port+'/atmail_webmail_normalized_ver/'+kb_dir+'/'+display_version);
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER || isnull(version))
  audit(AUDIT_UNKNOWN_WEB_APP_VER, "Atmail Webmail", install_url);

if (ver_compare(ver:version, fix:'6.3.5', strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version + ' ('+display_version+')' +
      '\n  Fixed version     : 6.3.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Atmail Webmail", install_url, version);
