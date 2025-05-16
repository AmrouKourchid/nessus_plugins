#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85690);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");


  script_name(english:"OpenSSH 7.x < 7.1 PermitRootLogin Security Bypass");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is 7.x prior to 7.1. It is, therefore, affected by a security
bypass vulnerability due to a logic error that is triggered under
certain compile-time configurations when PermitRootLogin is set to
'prohibit-password' or 'without-password'. An unauthenticated, remote
attacker can exploit this to permit password authentication to root
while preventing other forms of authentication.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2024 Tenable, Inc.");

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
  { 'min_version': '7.0', 'fixed_version' : '7.1' }
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
