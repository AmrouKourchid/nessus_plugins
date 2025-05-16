#
# This script was written by Thomas reinke <reinke@e-softinc.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, changed family (8/18/09)


include("compat.inc");

if (description)
{
  script_id(10883);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2002-0083");
  script_bugtraq_id(4241);

  script_name(english:"OpenSSH < 3.1 Channel Code Off by One Remote Privilege Escalation");
  script_summary(english:"Checks for the remote OpenSSH version");
 
  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
  script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH which is older than 3.1.

Versions prior than 3.1 are vulnerable to an off by one error
that allows local users to gain root access, and it may be
possible for remote users to similarly compromise the daemon
for remote access.

In addition, a vulnerable SSH client may be compromised by
connecting to a malicious SSH daemon that exploits this
vulnerability in the client code, thus compromising the
client system." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.1 or apply the patch for
prior versions. (See: http://www.openssh.org)" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);
	
  script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/07");
  script_set_attribute(attribute:"vuln_publication_date", value: "2002/03/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  
  script_copyright(english:"This script is Copyright (c) 2002-2024 Thomas Reinke");

  script_dependencies("openssh_detect.nbin");
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
  {'min_version': '2.0', 'fixed_version' : '3.1p1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
