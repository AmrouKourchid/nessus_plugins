#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0525-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190754);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id(
    "CVE-2019-14889",
    "CVE-2020-1730",
    "CVE-2020-16135",
    "CVE-2021-3634",
    "CVE-2023-1667",
    "CVE-2023-2283",
    "CVE-2023-6004",
    "CVE-2023-6918",
    "CVE-2023-48795"
  );
  script_xref(name:"IAVA", value:"2020-A-0203");
  script_xref(name:"IAVA", value:"2022-A-0041-S");
  script_xref(name:"IAVA", value:"2023-A-0517-S");
  script_xref(name:"IAVA", value:"2023-A-0703");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0525-1");

  script_name(english:"SUSE SLES15 Security Update : libssh (SUSE-SU-2024:0525-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0525-1 advisory.

  - A flaw was found with the libssh API function ssh_scp_new() in versions before 0.9.3 and before 0.8.8.
    When the libssh SCP client connects to a server, the scp command, which includes a user-provided path, is
    executed on the server-side. In case the library is used in a way where users can influence the third
    parameter of the function, it would become possible for an attacker to inject arbitrary commands, leading
    to a compromise of the remote target. (CVE-2019-14889)

  - libssh 0.9.4 has a NULL pointer dereference in tftpserver.c if ssh_buffer_new returns NULL.
    (CVE-2020-16135)

  - A flaw was found in libssh versions before 0.8.9 and before 0.9.4 in the way it handled AES-CTR (or DES
    ciphers if enabled) ciphers. The server or client could crash when the connection hasn't been fully
    initialized and the system tries to cleanup the ciphers when closing the connection. The biggest threat
    from this vulnerability is system availability. (CVE-2020-1730)

  - A flaw has been found in libssh in versions prior to 0.9.6. The SSH protocol keeps track of two shared
    secrets during the lifetime of the session. One of them is called secret_hash and the other session_id.
    Initially, both of them are the same, but after key re-exchange, previous session_id is kept and used as
    an input to new secret_hash. Historically, both of these buffers had shared length variable, which worked
    as long as these buffers were same. But the key re-exchange operation can also change the key exchange
    method, which can be based on hash of different size, eventually creating secret_hash of different size
    than the session_id has. This becomes an issue when the session_id memory is zeroed or when it is used
    again during second key re-exchange. (CVE-2021-3634)

  - A NULL pointer dereference was found In libssh during re-keying with algorithm guessing. This issue may
    allow an authenticated client to cause a denial of service. (CVE-2023-1667)

  - A vulnerability was found in libssh, where the authentication check of the connecting client can be
    bypassed in the`pki_verify_data_signature` function in memory allocation problems. This issue may happen
    if there is insufficient memory or the memory usage is limited. The problem is caused by the return value
    `rc,` which is initialized to SSH_ERROR and later rewritten to save the return value of the function call
    `pki_key_check_hash_compatible.` The value of the variable is not changed between this point and the
    cryptographic verification. Therefore any error between them calls `goto error` returning SSH_OK.
    (CVE-2023-2283)

  - The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other
    products, allows remote attackers to bypass integrity checks such that some packets are omitted (from the
    extension negotiation message), and a client and server may consequently end up with a connection for
    which some security features have been downgraded or disabled, aka a Terrapin attack. This occurs because
    the SSH Binary Packet Protocol (BPP), implemented by these extensions, mishandles the handshake phase and
    mishandles use of sequence numbers. For example, there is an effective attack against SSH's use of
    ChaCha20-Poly1305 (and CBC with Encrypt-then-MAC). The bypass occurs in chacha20-poly1305@openssh.com and
    (if CBC is used) the -etm@openssh.com MAC algorithms. This also affects Maverick Synergy Java SSH API
    before 3.1.0-SNAPSHOT, Dropbear through 2022.83, Ssh before 5.1.1 in Erlang/OTP, PuTTY before 0.80,
    AsyncSSH before 2.14.2, golang.org/x/crypto before 0.17.0, libssh before 0.10.6, libssh2 through 1.11.0,
    Thorn Tech SFTP Gateway before 3.4.6, Tera Term before 5.1, Paramiko before 3.4.0, jsch before 0.2.15,
    SFTPGo before 2.5.6, Netgate pfSense Plus through 23.09.1, Netgate pfSense CE through 2.7.2, HPN-SSH
    through 18.2.0, ProFTPD before 1.3.8b (and before 1.3.9rc2), ORYX CycloneSSH before 2.3.4, NetSarang
    XShell 7 before Build 0144, CrushFTP before 10.6.0, ConnectBot SSH library before 2.2.22, Apache MINA sshd
    through 2.11.0, sshj through 0.37.0, TinySSH through 20230101, trilead-ssh2 6401, LANCOM LCOS and
    LANconfig, FileZilla before 3.66.4, Nova before 11.8, PKIX-SSH before 14.4, SecureCRT before 9.4.3,
    Transmit5 before 5.10.4, Win32-OpenSSH before 9.5.0.0p1-Beta, WinSCP before 6.2.2, Bitvise SSH Server
    before 9.32, Bitvise SSH Client before 9.33, KiTTY through 0.76.1.13, the net-ssh gem 7.2.0 for Ruby, the
    mscdex ssh2 module before 1.15.0 for Node.js, the thrussh library before 0.35.1 for Rust, and the Russh
    crate before 0.40.2 for Rust. (CVE-2023-48795)

  - A flaw was found in libssh. By utilizing the ProxyCommand or ProxyJump feature, users can exploit
    unchecked hostname syntax on the client. This issue may allow an attacker to inject malicious code into
    the command of the features mentioned through the hostname parameter. (CVE-2023-6004)

  - A flaw was found in the libssh implements abstract layer for message digest (MD) operations implemented by
    different supported crypto backends. The return values from these were not properly checked, which could
    cause low-memory situations failures, NULL dereferences, crashes, or usage of the uninitialized memory as
    an input for the KDF. In this case, non-matching keys will result in decryption/integrity failures,
    terminating the connection. (CVE-2023-6918)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218209");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017947.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfde76e2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6918");
  script_set_attribute(attribute:"solution", value:
"Update the affected libssh-config, libssh-devel, libssh4 and / or libssh4-32bit packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libssh4-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libssh4-32bit-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libssh4-32bit-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libssh4-32bit-0.9.8-150200.13.3.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libssh4-32bit-0.9.8-150200.13.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libssh-config-0.9.8-150200.13.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libssh-devel-0.9.8-150200.13.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libssh4-0.9.8-150200.13.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssh-config / libssh-devel / libssh4 / libssh4-32bit');
}
