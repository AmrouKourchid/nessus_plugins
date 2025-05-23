#%NASL_MIN_LEVEL 70300
#
# This script was written by Filipe Custodio <filipecustodio@yahoo.com>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable :
# - description slightly modified to

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10492);
  script_version("1.49");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2000-0071", "CVE-2000-0098", "CVE-2000-0302");
  script_bugtraq_id(1065);
  script_xref(name:"MSFT", value:"MS00-006");
  script_xref(name:"MSKB", value:"251170");
  script_xref(name:"MSKB", value:"252463");

  script_name(english:"MS00-006: Microsoft IIS IDA/IDQ Multiple Vulnerabilities (uncredentialed check)");

  script_set_attribute(attribute:"synopsis", value:
"The remote IIS web server is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The remote version of IIS is affected by two vulnerabilities :

  - An information disclosure issue allows a remote attacker
    to obtain the real pathname of the document root by
    requesting nonexistent files with .ida or .idq
    extensions.

  - An argument validation issue in the WebHits component lets
    a remote attacker read arbitrary files on the remote
    server.

The path disclosure issue has been reported to affect Microsoft Index
Server as well.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2000/ms00-006");
  script_set_attribute(attribute:"solution", value:
"Microsoft released a patch for Windows 2000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2024 Filipe Custodio");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80, embedded:TRUE);


sig = get_http_banner(port:port);
if ( "IIS" >!< sig ) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);

 req = http_get(item:"/anything.idq", port:port);
 soc = http_open_socket(port);
 if(!soc)exit(0);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
 str = tolower(str);

 if ( egrep(pattern:"[a-z]\:\\.*anything",string:str) ) {
   security_warning( port:port );
 } else {
   req = http_get(item:"/anything.ida", port:port);
   soc = http_open_socket(port);
   if(!soc)exit(0);
   send(socket:soc, data:req);
   r = http_recv(socket:soc);
   http_close_socket(soc);
   str = egrep( pattern:"^<HTML>", string:r ) - "<HTML>";
   str = tolower(str);
   if ( egrep(pattern:"[a-z]\:\\.*anything", string:str) )
      security_warning( port:port );
   }
}
