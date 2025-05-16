#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201194);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/11");

  script_cve_id("CVE-2024-6387", "CVE-2024-39894");
  script_xref(name:"IAVA", value:"2024-A-0375-S");

  script_name(english:"OpenSSH < 9.8 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH installed on the remote host is prior to 9.8. It is, therefore, affected by a vulnerability as
referenced in the release-9.8 advisory.

  - This release contains fixes for two security problems, one critical and one minor. 1) Race condition in
    sshd(8) A critical vulnerability in sshd(8) was present in Portable OpenSSH versions between 8.5p1 and
    9.7p1 (inclusive) that may allow arbitrary code execution with root privileges. Successful exploitation
    has been demonstrated on 32-bit Linux/glibc systems with ASLR. Under lab conditions, the attack requires
    on average 6-8 hours of continuous connections up to the maximum the server will accept. Exploitation on
    64-bit systems is believed to be possible but has not been demonstrated at this time. It's likely that
    these attacks will be improved upon. Exploitation on non-glibc systems is conceivable but has not been
    examined. Systems that lack ASLR or users of downstream Linux distributions that have modified OpenSSH to
    disable per-connection ASLR re-randomisation (yes - this is a thing, no - we don't understand why) may
    potentially have an easier path to exploitation. OpenBSD is not vulnerable. We thank the Qualys Security
    Advisory Team for discovering, reporting and demonstrating exploitability of this problem, and for
    providing detailed feedback on additional mitigation measures. 2) Logic error in ssh(1)
    ObscureKeystrokeTiming In OpenSSH version 9.5 through 9.7 (inclusive), when connected to an OpenSSH server
    version 9.5 or later, a logic error in the ssh(1) ObscureKeystrokeTiming feature (on by default) rendered
    this feature ineffective - a passive observer could still detect which network packets contained real
    keystrokes when the countermeasure was active because both fake and real keystroke packets were being sent
    unconditionally. This bug was Daniel Hugenroth and Alastair Beresford of the University of Cambridge
    Computer Lab. Worse, the unconditional sending of both fake and real keystroke packets broke another long-
    standing timing attack mitigation. Since OpenSSH 2.9.9 sshd(8) has sent fake keystoke echo packets for
    traffic received on TTYs in echo-off mode, such as when entering a password into su(8) or sudo(8). This
    bug rendered these fake keystroke echoes ineffective and could allow a passive observer of a SSH session
    to once again detect when echo was off and obtain fairly limited timing information about keystrokes in
    this situation (20ms granularity by default). This additional implication of the bug was identified by
    Jacky Wei En Kung, Daniel Hugenroth and Alastair Beresford and we thank them for their detailed analysis.
    This bug does not affect connections when ObscureKeystrokeTiming was disabled or sessions where no TTY was
    requested. (openssh-9.8-1)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 9.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH");
  script_require_ports("Services/ssh", 22);

  exit(0);
}
include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

var banner = get_kb_item("SSH/banner/" + port);
if (
  'SSH-2.0-OpenSSH_9.7 with CVE-2024-6387,CVE-2024-39894 fixes' >< banner &&
  report_paranoia < 2)
  audit(AUDIT_LISTEN_NOT_VULN, 'OpenSSH', port);

var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version':'8.5p1', 'max_version':'9.7p1', 'fixed_version':'9.8p1', 'fixed_display':'9.8p1 / 9.8'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
