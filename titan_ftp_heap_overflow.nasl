#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(14591);
 script_cve_id("CVE-2004-1641");
 script_bugtraq_id(11069);
 script_version("1.19");

 script_name(english:"Titan FTP Server Multiple Command Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a 
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote is running Titan FTP Server. All versions up to 
and including 3.21 are reported vulnerable to a remote heap 
overflow in the CWD, STAT or LIST command processing.

An attacker may deny service to legitimate users or execute 
arbitrary code on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Titan FTP NextGen 2.0.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-1641");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

include("ftp_func.inc");
include("debug.inc");

var port = get_ftp_port(default: 21);
var banner = get_ftp_banner(port:port);
dbg::detailed_log(lvl:2,msg:banner);

if (!banner || " Titan FTP Server" >!< banner) exit(0);

if (safe_checks())
{
  # Identify the version.
  version = strstr(banner, " Titan FTP Server ") - " Titan FTP Server ";
  version = version - strstr(version, " Ready");

  if (version)
  {
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      ver[0] < 6 ||
      (
        ver[0] == 6 && 
        (
          ver[1] < 26 ||
          (ver[1] == 26 && ver[2] < 631)
        )
      )
    )
    {
      if (report_verbosity)
      {
        version_ui = strcat(ver[0], ".", ver[1], " Build ", ver[2]);
        report = strcat(
          "Titan FTP ", version_ui, " appears to be running on the remote host. ",
          "Note that Nessus did not actually try to exploit this issue because ",
          "safe checks were enabled when the scan was run."
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
    }
  }
  exit(0);
}
