#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90023);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id("CVE-2016-3115");
  script_xref(name:"EDB-ID", value:"39569");

  script_name(english:"OpenSSH < 7.2p2 X11Forwarding xauth Command Injection");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.2p2. It is, therefore, affected by a security
bypass vulnerability due to improper sanitization of X11
authentication credentials. An authenticated, remote attacker can
exploit this, via crafted credentials, to inject arbitrary xauth
commands, resulting in gaining read and write access to arbitrary
files, connecting to local ports, or performing further attacks on
xauth itself. Note that exploiting this vulnerability requires
X11Forwarding to have been enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.2p2");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/x11fwd.adv");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.2p2 / 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

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

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'fixed_version' : '7.2p2', 'fixed_display': '7.2p2 / 7.3'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
