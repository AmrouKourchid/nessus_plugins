#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10439);
 script_version("1.30");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 script_cve_id("CVE-2000-0525");
 script_bugtraq_id(1334);

 script_name(english:"OpenSSH < 2.1.1 UseLogin Local Privilege Escalation");
 script_summary(english:"Checks for the remote OpenSSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a local 
privilege escalation vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be 
running OpenSSH version older than 2.1.1. Such versions are
reportedly affected by a local privilege esclation 
vulnerability.

If the UseLogin option is enabled, then sshd does not switch
to the uid of the user logging in.  Instead, sshd relies on 
login(1) to do the job.  However, if the user specifies a 
command for remote execution, login(1) cannot be used and 
sshd fails to set the correct user id, so the command is run 
with the same privilege as sshd (usually root privileges)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.1.1 or make sure that the 
option UseLogin is set to no in sshd_config" );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/06");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  {'fixed_version' : '2.1.1'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
