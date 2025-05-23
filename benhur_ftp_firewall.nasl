#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
  script_id(11052);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2002-2307");
  script_bugtraq_id(5279);

  script_name(english:"BenHur Firewall Source Port 20 ACL Restriction Bypass");
  script_summary(english:"Connects to a few services with sport = 20");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass the firewall on the remote host." );
  script_set_attribute(attribute:"description", value:
"It is possible to connect to firewall-protected ports on the remote
host by setting the source port to 20. An attacker may use this 
flaw to access services that should not be accessible to outsiders 
on this host." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e608b229" );
  script_set_attribute(attribute:"solution", value:
"Update to 066 fix 2 or:

Reconfigure your firewall to reject any traffic coming from port 20." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-2307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2002-2024 Tenable Network Security, Inc.");

  exit(0);
}

if(islocalhost() || NASL_LEVEL < 2204 )exit(0);

# nb: port 8888 on a BenHur firewall is the Web administration port
#     and normally will not be accessible.
var port = 8888;
if ( get_kb_item("Ports/tcp/"+port) ) exit(0, "Port "+port+" is known to be open. This does not look like a BenHur firewall.");

var soc = open_sock_tcp(port);
if ( soc ) 
{
  close(soc);
  exit(0, "Nessus was able to open a socket on port "+port+" using an unprivileged source port.");
}

soc = open_priv_sock_tcp(sport:20, dport:port);
if ( ! soc ) exit(0, "Nessus was not able to open a socket on port "+port+" using a privileged source port.");

send(socket:soc, data:'GET / HTTP/1.0\r\n\r\n');
var res = recv_line(socket:soc, length:4096);
close(soc);
if (preg(pattern:"^HTTP/.*", string:res))
{
  var report = 'Nessus was able to connect to port 8888 by sending an HTTP request to the remote host from source port 20:\n\n' +
    'Nessus received the following response from the server:\n\n' + res + '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else exit(0, "The service listening on port "+port+" is not affected.");
