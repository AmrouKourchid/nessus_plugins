#%NASL_MIN_LEVEL 70300
# 
# This script is Copyright (C) 2003-2007 SensePost");
#
# Modification by David Maciejak
# <david dot maciejak at kyxar dot fr>
# based on 404print.c from Digital Defense
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11874);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_name(english:"Microsoft IIS 404 Response Service Pack Signature");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running Microsoft IIS.");
  script_set_attribute(attribute:"description", value:
"The Patch level (Service Pack) of the remote IIS server appears to be
lower than the current IIS service pack level.  As each service pack
typically contains many security patches, the server may be at risk. 

Note that this test makes assumptions of the remote patch level based
on static return values (Content-Length) within a IIS Server's 404
error message.  As such, the test can not be totally reliable and
should be manually confirmed. 

Note also that, to determine IIS6 patch levels, a simple test is done
based on strict RFC 2616 compliance.  It appears as if IIS6-SP1 will
accept CR as an end-of-line marker instead of both CR and LF.");
  script_set_attribute(attribute:"solution", value:
"Ensure that the server is running the latest stable Service Pack.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2020 SensePost & Copyright (C) 2004-2011 David Maciejak");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");




port = get_http_port(default:80, embedded:TRUE);

sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);
if(! get_port_state(port)) exit(0);
r1 = http_get(item:"/nessus" + rand(), port:port);

r  = http_keepalive_send_recv(data:r1, port:port);
if ( r == NULL ) exit(0);
if (!ereg(pattern:"^HTTP.* 404 .*", string:r))exit(0);

v4 = egrep(pattern:"^Server:.*Microsoft-IIS/4\.0", string:r);
v5 = egrep(pattern:"^Server:.*Microsoft-IIS/5\.0", string:r);
v51 = egrep(pattern:"^Server:.*Microsoft-IIS/5\.1", string:r);
v6 = egrep(pattern:"^Server:.*Microsoft-IIS/6\.0", string:r);

cltmp = eregmatch(pattern:".*Content-Length: ([0-9]+).*", string:r);
if (isnull(cltmp)) exit(0);
cl=int(cltmp[1]);

ver = string("The remote IIS server *seems* to be ");

#if(v4)
#{
#        if (102 == cl)
#                ver = ver + string("Microsoft IIS 4 - Sp0\n");		
#	if (451 == cl)
#		ver = ver + string("Microsoft IIS 4 - SP6\n");
#	if (461 == cl)
#		ver = ver + string("Microsoft IIS 4 - SP3\n");
#}

if(v5)
{
#??
#        if(111 == cl)
#		ver = ver + string("Microsoft IIS 5 - SP4\n");
	if(3243 == cl)
		ver = ver + string("Microsoft IIS 5 - SP0 or SP1\n");
        if(2352 == cl)
                ver = ver + string("Microsoft IIS 5 - SP2 or SRP1\n");
        if(4040 == cl)
                ver = ver + string("Microsoft IIS 5 - SP3 or SP4\n");
}

if(v51)
{
        if (1330 == cl)
                ver = ver + string("Microsoft IIS 5.1 - SP2\n");		
	if (4040 == cl)
		ver = ver + string("Microsoft IIS 5.1 - SP0\n");
}

if(v6)
{
        #if (2166 == cl)
                #ver = ver + string("Microsoft IIS 6.0 - SP0\n");		
	#if (1635 == cl)
		#ver = ver + string("Microsoft IIS 6.0 - w2k3 build 3790\n");

        a = string("HEAD / HTTP/1.0\n\r\n");
        soc = http_open_socket(port);
        if(soc)
        {
                send(socket:soc, data: a);
                r = recv(socket:soc, length:4096);
                if(r =~ "200 OK") ver = ver + string("Microsoft IIS 6.0 - SP1\n");
                if(r =~ "400 Bad Request") ver = ver + string("Microsoft IIS 6.0 - SP0\n");
        }

}

if ( ver !=  "The remote IIS server *seems* to be " ) 
{
  security_note(port:port, extra:ver);
}
