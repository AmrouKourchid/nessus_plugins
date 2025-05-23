#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10171);
  script_version("1.37");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-1999-1068");

  script_name(english:"Oracle Webserver PL/SQL Stored Procedure GET Request DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash by 
supplying a too long argument to the cgi /ews-bin/fnord. 
An attacker may use this flaw to prevent your customers 
to access your website.");
  script_set_attribute(attribute:"solution", value:
"Remove this CGI.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"1997/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 1999-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_require_keys("Settings/ParanoidReport");
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

if (report_paranoia < 2)
 exit(0, "This script is prone to FP and only runs in 'paranoid' mode");

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(1, "the web server on port "+port+" is dead");

res = is_cgi_installed3(item:"/ews-bin/fnord", port:port);
if(res)
{
  request = string("/ews-bin/fnord?foo=", crap(2048));
  is_cgi_installed3(item:request, port:port);
  sleep(5);
  if (http_is_dead(port: port, retry: 3)) security_warning(port);
}

