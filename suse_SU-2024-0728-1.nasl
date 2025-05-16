#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0728-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(191640);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/06");

  script_cve_id(
    "CVE-2023-46809",
    "CVE-2024-22019",
    "CVE-2024-22025",
    "CVE-2024-24758",
    "CVE-2024-24806"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0728-1");

  script_name(english:"SUSE SLES15 Security Update : nodejs16 (SUSE-SU-2024:0728-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:0728-1 advisory.

  - A vulnerability in the privateDecrypt() API of the crypto library, allowed a covert timing side-channel
    during PKCS#1 v1.5 padding error handling. The vulnerability revealed significant timing differences in
    decryption for valid and invalid ciphertexts. This poses a serious threat as attackers could remotely
    exploit the vulnerability to decrypt captured RSA ciphertexts or forge signatures, especially in scenarios
    involving API endpoints processing Json Web Encryption messages. Impacts: Thank you, to hkario for
    reporting this vulnerability and thank you Michael Dawson for fixing it. (CVE-2023-46809)

  - A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with
    chunked encoding, leading to resource exhaustion and denial of service (DoS). The server reads an
    unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension
    bytes. The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like
    timeouts and body size limits. (CVE-2024-22019)

  - Node.js reports: Code injection and privilege escalation through Linux capabilities- (High) http: Reading
    unprocessed HTTP request with unbounded chunk extension allows DoS attacks- (High) Path traversal by
    monkey-patching Buffer internals- (High) setuid() does not drop all privileges due to io_uring - (High)
    Node.js is vulnerable to the Marvin Attack (timing variant of the Bleichenbacher attack against PKCS#1
    v1.5 padding) - (Medium) Multiple permission model bypasses due to improper path traversal sequence
    sanitization - (Medium) Improper handling of wildcards in --allow-fs-read and --allow-fs-write (Medium)
    Denial of Service by resource exhaustion in fetch() brotli decoding - (Medium) (CVE-2024-22025)

  - Undici is an HTTP/1.1 client, written from scratch for Node.js. Undici already cleared Authorization
    headers on cross-origin redirects, but did not clear `Proxy-Authentication` headers. This issue has been
    patched in versions 5.28.3 and 6.6.1. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2024-24758)

  - libuv is a multi-platform support library with a focus on asynchronous I/O. The `uv_getaddrinfo` function
    in `src/unix/getaddrinfo.c` (and its windows counterpart `src/win/getaddrinfo.c`), truncates hostnames to
    256 characters before calling `getaddrinfo`. This behavior can be exploited to create addresses like
    `0x00007f000001`, which are considered valid by `getaddrinfo` and could allow an attacker to craft
    payloads that resolve to unintended IP addresses, bypassing developer checks. The vulnerability arises due
    to how the `hostname_ascii` variable (with a length of 256 bytes) is handled in `uv_getaddrinfo` and
    subsequently in `uv__idna_toascii`. When the hostname exceeds 256 characters, it gets truncated without a
    terminating null byte. As a result attackers may be able to access internal APIs or for websites (similar
    to MySpace) that allows users to have `username.example.com` pages. Internal services that crawl or cache
    these user pages can be exposed to SSRF attacks if a malicious user chooses a long vulnerable username.
    This issue has been addressed in release version 1.48.0. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2024-24806)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220053");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-March/018084.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df61a2b6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24806");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs16, nodejs16-devel, nodejs16-docs and / or npm16 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm16");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'nodejs16-docs-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'nodejs16-docs-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'nodejs16-docs-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'nodejs16-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'nodejs16-devel-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'npm16-16.20.2-150400.3.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs16 / nodejs16-devel / nodejs16-docs / npm16');
}
