#
# (C) Tenable, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10608);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 script_cve_id("CVE-2001-1585");
 script_bugtraq_id(2356);

 script_name(english:"OpenSSH 2.3.1 SSHv2 Public Key Authentication Bypass");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSH 2.3.1.

This version is vulnerable to a flaw that allows any attacker who can
obtain the public key of a valid SSH user to log into this host
without any authentication." );
 script_set_attribute(attribute:"see_also", value:"http://www.openbsd.org/advisories/ssh_bypass.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 2.3.2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(287);
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/08");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2024 Tenable, Inc.");
 script_family(english:"Misc.");

 script_dependencie("openssh_detect.nbin");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

# 2.3.1 was a dev build that never released and there is no evidence that a portable 2.3.1p1 was released
if (app_info.portable)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, app_info.version);

var constraints = [
  {'min_version': '2.3.1', 'fixed_version': '2.3.2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
