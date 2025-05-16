#
# (C) Tenable, Inc.
#

# Ref:
# From: Damien Miller <djm@cvs.openbsd.org>
# To: openssh-unix-announce@mindrot.org
# Subject: Multiple PAM vulnerabilities in portable OpenSSH
# also covers CVE-2001-1380


include("compat.inc");

if (description)
{
 script_id(11848);
 script_version("1.28");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

 script_cve_id("CVE-2003-0786", "CVE-2003-0787");
 script_bugtraq_id(8677);
 script_xref(name:"CERT", value:"602204");
 
 script_name(english:"OpenSSH < 3.7.1p2 Multiple Remote Vulnerabilities");
 script_summary(english:"Checks for the remote SSH version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application which may allow an 
attacker to login potentially as root without password." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host appears to be
running OpenSSH 3.7p1 or 3.7.1p1. These versions are 
vulnerable to a flaw in the way they handle PAM 
authentication when PrivilegeSeparation is disabled.

Successful exploitation of this issue may allow an 
attacker to gain a shell on the remote host using a
null password." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 3.7.1p2 or disable PAM support in sshd_config" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/09/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 
 script_dependencie("openssh_detect.nbin", "os_fingerprint.nasl");
 script_require_keys("installed_sw/OpenSSH");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

# Windows not affected.
os = get_kb_item("Host/OS");
if (!get_kb_item("Settings/PCI_DSS") && !isnull(os))
{
  if ("Linux" >!< os && "SCO" >!< os) exit(0);
}

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

# only the two portable versions mentioned are vulnerable
if (!app_info.portable)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, app_info.version);

var constraints = [
  {'equal': '3.7p1', 'fixed_version' : '3.7.1p2'},
  {'equal': '3.7.1p1', 'fixed_version' : '3.7.1p2'},
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);