#
# (C) Tenable, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31737);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2008-1483", "CVE-2008-3234");
  script_bugtraq_id(28444);
  script_xref(name:"Secunia", value:"29522");

  script_name(english:"OpenSSH X11 Forwarding Session Hijacking");
  script_summary(english:"Checks OpenSSH server version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is prone to an X11 session hijacking
vulnerability." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of SSH installed on the remote
host is older than 5.0.  Such versions may allow a local user to
hijack X11 sessions because it improperly binds TCP ports on the local
IPv6 interface if the corresponding ports on the IPv4 interface are in
use." );
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=463011" );
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-5.0" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 5.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);
  script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/03");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2008-2024 Tenable, Inc.");

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
  {'fixed_version': '5.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
