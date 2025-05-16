#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187201);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2023-48795", "CVE-2023-51384", "CVE-2023-51385");
  script_xref(name:"IAVA", value:"2023-A-0701-S");

  script_name(english:"OpenSSH < 9.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH installed on the remote host is prior to 9.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the release-9.6 advisory.

  - ssh(1), sshd(8): implement protocol extensions to thwart the so-called Terrapin attack discovered by
    Fabian Bumer, Marcus Brinkmann and Jrg Schwenk. This attack allows a MITM to effect a limited break of
    the integrity of the early encrypted SSH transport protocol by sending extra messages prior to the
    commencement of encryption, and deleting an equal number of consecutive messages immediately after
    encryption starts. A peer SSH client/server would not be able to detect that messages were deleted. While
    cryptographically novel, the security impact of this attack is fortunately very limited as it only allows
    deletion of consecutive messages, and deleting most messages at this stage of the protocol prevents user
    user authentication from proceeding and results in a stuck connection. The most serious identified impact
    is that it lets a MITM to delete the SSH2_MSG_EXT_INFO message sent before authentication starts, allowing
    the attacker to disable a subset of the keystroke timing obfuscation features introduced in OpenSSH 9.5.
    There is no other discernable impact to session secrecy or session integrity. OpenSSH 9.6 addresses this
    protocol weakness through a new strict KEX protocol extension that will be automatically enabled when
    both the client and server support it. This extension makes two changes to the SSH transport protocol to
    improve the integrity of the initial key exchange. Firstly, it requires endpoints to terminate the
    connection if any unnecessary or unexpected message is received during key exchange (including messages
    that were previously legal but not strictly required like SSH2_MSG_DEBUG). This removes most malleability
    from the early protocol. Secondly, it resets the Message Authentication Code counter at the conclusion of
    each key exchange, preventing previously inserted messages from being able to make persistent changes to
    the sequence number across completion of a key exchange. Either of these changes should be sufficient to
    thwart the Terrapin Attack. More details of these changes are in the PROTOCOL file in the OpenSSH source
    distribition. (CVE-2023-48795)

  - ssh-agent(1): when adding PKCS#11-hosted private keys while specifying destination constraints, if the
    PKCS#11 token returned multiple keys then only the first key had the constraints applied. Use of regular
    private keys, FIDO tokens and unconstrained keys are unaffected. (CVE-2023-51384)

  - ssh(1): if an invalid user or hostname that contained shell metacharacters was passed to ssh(1), and a
    ProxyCommand, LocalCommand directive or match exec predicate referenced the user or hostname via %u, %h
    or similar expansion token, then an attacker who could supply arbitrary user/hostnames to ssh(1) could
    potentially perform command injection depending on what quoting was present in the user-supplied
    ssh_config(5) directive. This situation could arise in the case of git submodules, where a repository
    could contain a submodule with shell characters in its user/hostname. Git does not ban shell
    metacharacters in user or host names when checking out repositories from untrusted sources. Although we
    believe it is the user's responsibility to ensure validity of arguments passed to ssh(1), especially
    across a security boundary such as the git example above, OpenSSH 9.6 now bans most shell metacharacters
    from user and hostnames supplied via the command-line. This countermeasure is not guaranteed to be
    effective in all situations, as it is infeasible for ssh(1) to universally filter shell metacharacters
    potentially relevant to user-supplied commands. User/hostnames provided via ssh_config(5) are not subject
    to these restrictions, allowing configurations that use strange names to continue to be used, under the
    assumption that the user knows what they are doing in their own configuration files. (CVE-2023-51385)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 9.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51385");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

# avoid FP on junos
if (report_paranoia < 2 &&
  !(empty_or_null(get_kb_item('Host/Juniper/show_ver'))))
  audit(AUDIT_OS_NOT, 'affected');

var constraints = [
  {'fixed_version': '9.6p1', 'fixed_display': '9.6p1 / 9.6'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);