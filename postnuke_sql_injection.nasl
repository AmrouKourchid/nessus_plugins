#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11744);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");
  script_bugtraq_id(7697);

  script_name(english:"PostNuke Glossary Module page Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to a SQL Injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of PostNuke which is vulnerable
to a SQL injection attack.

An attacker may use this flaw to gain the control of the database
of this host.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of PostNuke.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postnuke_software_foundation:postnuke");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2024 Tenable Network Security, Inc.");

  script_dependencies("postnuke_detect.nasl");
  script_require_keys("www/postnuke");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/postnuke" );
if ( ! kb ) exit(0);
stuff = eregmatch(pattern:"(.*) under (.*)", string:kb );
dir = stuff[2];


if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

r = http_send_recv3(method: "GET", port: port, item:string(dir, "/modules.php?op=modload&name=Glossary&file=index&page='"));
if (isnull(r)) exit(0);
 
if ("hits=hits+1 WHERE" >< r[0]+r[1]+r[2])
{
 security_hole(port);
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

