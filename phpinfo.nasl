#%NASL_MIN_LEVEL 70300
#
# This script was written by Randy Matz <rmatz@ctusa.net>
#
# Improvement by rd: look in every dir for info.php and phpinfo.php
# not just in cgi-bin

# Changes by Tenable:
# - Revised plugin title (4/24/2009)
# - Added parsing of PHP version and setting of KB items (8/30/2013)

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11229);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/22");

  script_name(english:"Web Server info.php / phpinfo.php Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
information disclosure attack.");
  script_set_attribute(attribute:"description", value:
"Many PHP installation tutorials instruct the user to create a PHP file
that calls the PHP function 'phpinfo()' for debugging purposes. 
Various PHP applications may also include such a file.  By accessing
such a file, a remote attacker can discover a large amount of
information about the remote web server, including :

  - The username of the user who installed PHP and if they
    are a SUDO user.

  - The IP address of the host.

  - The version of the operating system.

  - The web server version.

  - The root directory of the web server. 

  - Configuration information about the remote PHP 
    installation.");
  script_set_attribute(attribute:"solution", value:
"Remove the affected file(s).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from an analysis done by Tenable");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2024 Randy Matz");

  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

var port, dirs, rep, item, res, match, version, report;
var dbg = [];

port = get_http_port(default:80, embedded:TRUE);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests)
 dirs = get_kb_list("www/" + port + "/content/directories");
else
  dirs = cgi_dirs();
if(isnull(dirs))dirs = make_list("");
else dirs = list_uniq(make_list("", dirs));

rep = NULL;
foreach var dir (dirs)
{
 foreach var script (make_list("/phpinfo.php", "/info.php"))
 {
   item = dir + script;
   res = http_send_recv3(item:item, method:'GET', port:port);
   if( res == NULL ) exit(0);
   match = pgrep(pattern:"<title>(PHP [0-9.]+ - )?phpinfo\(\)<\/title>",string:res[2],icase:TRUE);
   if(match)
   {
     rep += '  - ' + build_url(port:port, qs:dir+script+'\n') ;
     
     version = pregmatch(pattern:"\>PHP Version (.+)\<", string:res[2]);
     if (!isnull(version))
     {
       version = version[1];
       set_kb_item(
         name  : "www/phpinfo/"+port+"/version/"+version,
         value : 'under ' + build_url(qs:dir+script, port:port)
       );
     }
     dbg['http_send_recv3'] = match;
     dbg['Endpoints'] += obj_rep(item);
     dbg['Version'] = version;
     dbg::detailed_log(lvl:3, msg: "[ + ] PHPINFO.NASL LOGS : " + '\n' + obj_rep(dbg) + '\n');
   }
 }
}

if(rep != NULL)
{
 if (report_verbosity)
 {
  if (max_index(split(rep)) > 1) var s = "s that call";
  else s = " that calls";

  report =
   '\n' +
   'Nessus discovered the following URL' + s + ' phpinfo() :\n' +
   '\n' +
   rep;
  security_warning(port:port, extra:report);
 }
 else security_warning(port);
}

