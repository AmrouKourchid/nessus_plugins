#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17744);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2004-1653");

  script_name(english:"OpenSSH >= 2.3.0 AllowTcpForwarding Port Bouncing");
  script_summary(english:"Checks for remote SSH version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server may permit anonymous port bouncing.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSH, version
2.3.0 or later.  Such versions of OpenSSH allow forwarding TCP
connections.  If the OpenSSH server is configured to allow anonymous
connections (e.g. AnonCVS), remote, unauthenticated users could use
the host as a proxy.");

  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=bugtraq&m=109413637313484&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c86d008");

  script_set_attribute(attribute:"solution", value:
"Disallow anonymous users, set AllowTcpForwarding to 'no', or use the
Match directive to restrict anonymous users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'min_version': '2.3.0', 'fixed_display': 'See vendor advisory'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
