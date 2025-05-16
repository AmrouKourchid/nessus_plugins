#
# This script is copyright  2001 by EMAZE Networks S.p.A.
# under the General Public License (GPL). All Rights Reserved.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID

# Changes by Tenable:
# - Updated title, xrefs, synopsis, and description (11/16/11)
# - Updated description, static report [RD]
# - Title update, output formatting, family change (8/18/09)


include("compat.inc");

if (description)
{
  script_id(10823);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2001-0872", "CVE-2001-1029");
  script_bugtraq_id(3614);

  script_name(english:"OpenSSH < 3.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for the remote SSH version");
 
  script_set_attribute(attribute:"synopsis", value:
"The SSH service running on the remote host has multiple
vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH which is older than 3.0.2.
Versions prior than 3.0.2 have the following vulnerabilities :

  - When the UseLogin feature is enabled, a local user
    could export environment variables, resulting in
    command execution as root.  The UseLogin feature is
    disabled by default. (CVE-2001-0872)

  - A local information disclosure vulnerability.
    Only FreeBSD hosts are affected by this issue.
    (CVE-2001-1029)");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Sep/208");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/releases/4.4R/errata.html");
  # http://lists.mindrot.org/pipermail/openssh-unix-announce/2001-December/000031.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f85ed76c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.0.2 or apply the patch for prior
versions. (Available at: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH)" );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
	
  script_set_attribute(attribute:"plugin_publication_date", value: "2001/12/10");
  script_set_attribute(attribute:"vuln_publication_date", value: "2001/12/03");
  script_set_attribute(attribute:"patch_publication_date", value: "2001/12/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is copyright (C) 2001-2024 by EMAZE Networks S.p.A.");
  script_family(english:"Misc.");

  script_dependencie("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version' : '3.0.2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
