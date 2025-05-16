#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, formatted output, enhanced solution, changed plugin family (8/18/09)


include("compat.inc");

if(description)
{
	script_id(10954);
	script_version("1.29");
	script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 	script_cve_id("CVE-2002-0575");
 	script_bugtraq_id(4560);
 
 	script_name(english:"OpenSSH Kerberos TGT/AFS Token Passing Remote Overflow");
 	script_summary(english:"Checks for the remote SSH version");
 
 	script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote host." );
 	script_set_attribute(attribute:"description", value:
"You are running a version of OpenSSH older than OpenSSH 3.2.1.

A buffer overflow exists in the daemon if AFS is enabled on
your system, or if the options KerberosTgtPassing or
AFSTokenPassing are enabled.  Even in this scenario, the
vulnerability may be avoided by enabling UsePrivilegeSeparation.

Versions prior to 2.9.9 are vulnerable to a remote root
exploit. Versions prior to 3.2.1 are vulnerable to a local
root exploit." );
 	script_set_attribute(attribute:"solution", value:
"Upgrade to version 3.2.1 or later." );
	script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
	script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
	script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
	script_set_attribute(attribute:"exploit_available", value:"true");

	script_set_attribute(attribute:"plugin_publication_date", value: "2002/05/12");
	script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/22");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_family(english:"Gain a shell remotely");
	
	script_copyright(english:"This script is Copyright (C) 2002-2024 Thomas Reinke");

 if (!defined_func("bn_random")) 
	script_dependencie("openssh_detect.nbin");
 else
	script_dependencie("openssh_detect.nbin", "redhat-RHSA-2002-131.nasl");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);
	exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

if (get_kb_item("CVE-2002-0640")) exit(0);

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version' : '3.2.1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
