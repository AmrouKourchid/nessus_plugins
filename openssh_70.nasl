#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85382);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id(
    "CVE-2015-5600",
    "CVE-2015-6563",
    "CVE-2015-6564",
    "CVE-2015-6565"
  );
  script_bugtraq_id(75990, 76317, 76497);
  script_xref(name:"EDB-ID", value:"41173");

  script_name(english:"OpenSSH < 7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.0. It is, therefore, affected by the following
vulnerabilities :

  - A security bypass vulnerability exists in the
    kbdint_next_device() function in file auth2-chall.c that
    allows the circumvention of MaxAuthTries during
    keyboard-interactive authentication. A remote attacker
    can exploit this issue to force the same authentication
    method to be tried thousands of times in a single pass
    by using a crafted keyboard-interactive 'devices'
    string, thus allowing a brute-force attack or causing a
    denial of service. (CVE-2015-5600)

  - A security bypass vulnerability exists in sshd due to
    improper handling of username data in
    MONITOR_REQ_PAM_INIT_CTX requests. A local attacker can
    exploit this, by sending a MONITOR_REQ_PWNAM request, to
    conduct an impersonation attack. Note that this issue
    only affects Portable OpenSSH. (CVE-2015-6563)

  - A privilege escalation vulnerability exists due to a
    use-after-free error in sshd that is triggered when
    handling a MONITOR_REQ_PAM_FREE_CTX request. A local
    attacker can exploit this to gain elevated privileges.
    Note that this issue only affects Portable OpenSSH.
    (CVE-2015-6564)

  - A local command execution vulnerability exists in sshd
    due to setting insecure world-writable permissions for
    TTYs. A local attacker can exploit this, by injecting
    crafted terminal escape sequences, to execute commands
    for logged-in users. (CVE-2015-6565)");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.0");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");

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
  {'fixed_version' : '7.0'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
