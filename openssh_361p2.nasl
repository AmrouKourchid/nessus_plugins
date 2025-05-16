#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17702);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2002-0746");

  script_name(english:"OpenSSH < 3.6.1p2 Multiple Vulnerabilities");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is ealier than 3.6.1p2.  When compiled for the AIX operating
system with a compiler other than that of the native AIX compiler, an
error exists that can allow dynamic libraries in the current directory
to be loaded before dynamic libraries in the system paths.  This
behavior can allow local users to escalate privileges by creating,
loading and executing their own malicious replacement libraries.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-3.6.1p2");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/320038/2003-04-25/2003-05-01/0");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 3.6.1p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# only affects portable OpenSSH on IBM's AIX OS
if (!app_info.portable)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port, app_info.version);

var constraints = [
  {'fixed_version' : '3.6.1p2'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
