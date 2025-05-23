#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added link to the Bugtraq message archive
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10372);
  script_version("1.35");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-1999-0360");
  script_bugtraq_id(1811);

  script_name(english:"Microsoft IIS repost.asp File Upload");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server supports arbitrary file uploads.");
  script_set_attribute(attribute:"description", value:
"The script '/scripts/repost.asp' is installed on the remote IIS web
server and allows an attacker to upload arbitrary files to the
'/Users' directory if it has not been configured properly.");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=91763097004101&w=2");
  script_set_attribute(attribute:"solution", value:
"Create the '/Users' directory if necessary and ensure that the
Anonymous Internet Account ('IUSER_MACHINE') only has read access to
it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2000-2024 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("Settings/ParanoidReport", "www/ASP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, asp:TRUE);

# nb: only run if report_paranoia == 2 since the plugin doesn't actually
#     check whether the script is configured securely.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

cgi = "/scripts/repost.asp";

res = http_send_recv3(method:"GET", item:cgi, port:port, exit_on_fail:TRUE);
headers = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(headers)) audit(AUDIT_RESP_BAD, port);

if (isnull(headers['$code'])) exit(1, "Failed to extract the HTTP status code in the response from the web server listening on port "+port+".");
code = headers['$code'];

if (code == 404) exit(0, "'"+cgi+"' was not found on the web server listening on port "+port+".");
else if (code != 200) exit(0, "An error was encountered when requesting '"+cgi+"' from the web server listening on port "+port+" (HTTP status code "+code+").");

if ("Here is your upload status" >< res[2]) security_hole(port);
else audit(AUDIT_LISTEN_NOT_VULN, "web server", port);
