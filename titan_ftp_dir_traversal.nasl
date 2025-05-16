#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14659);
 script_version("1.18");
 script_cve_id("CVE-2014-1842");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/26");

 script_xref(name:"Secunia", value:"8914");

 script_name(english:"Titan FTP Server quote stat Command Traversal Arbitrary Directory Listing");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"According to its banner, the version of Titan FTP Server running on
the remote host has a directory traversal vulnerability.  A remote
attacker could exploit this to view arbitrary files on the system."
 );
  # http://web.archive.org/web/20040223110816/http://dhgroup.org/bugs/adv21.txt
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?f82b50d3"
 );
 script_set_attribute(attribute:"solution",value:"Upgrade to Titan FTP NextGen 2.0.6 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1842");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/29");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:south_river_technologies:titan_ftp_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#the code

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
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }
  }
  exit(0);
}
