#
# (C) Tenable, Inc.
#


include("compat.inc");


if (description)
{
  script_id(17699);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2000-0143");

  script_name(english:"OpenSSH < 1.2.2 sshd Local TCP Redirection Connection Masking Weakness");
  script_summary(english:"Check OpenSSH banner version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host allows connections to be
redirected."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host allows local users without shell access to redirect TCP
connections with the IDENT 'root@localhost'.  A local attacker could
use this incorrect IDENT to bypass monitoring/logging."
  );
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Feb/200");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Feb/212");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2000/Feb/231");
  script_set_attribute(
    attribute:"solution",
    value:
"Either upgrade to OpenSSH 1.2.2 or later or use one of the 'IMMUNE
CONFIGURATIONS' referenced in the advisory titled
'sshd-restricted-users-incorrect-configuration'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2024 Tenable, Inc.");

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
  {'fixed_version': '1.2.2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

