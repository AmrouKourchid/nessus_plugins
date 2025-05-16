#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0643-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(191130);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2023-46809",
    "CVE-2024-21890",
    "CVE-2024-21891",
    "CVE-2024-21892",
    "CVE-2024-21896",
    "CVE-2024-22017",
    "CVE-2024-22019",
    "CVE-2024-22025",
    "CVE-2024-24758",
    "CVE-2024-24806"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0643-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : nodejs20 (SUSE-SU-2024:0643-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:0643-1 advisory.

  - A vulnerability in the privateDecrypt() API of the crypto library, allowed a covert timing side-channel
    during PKCS#1 v1.5 padding error handling. The vulnerability revealed significant timing differences in
    decryption for valid and invalid ciphertexts. This poses a serious threat as attackers could remotely
    exploit the vulnerability to decrypt captured RSA ciphertexts or forge signatures, especially in scenarios
    involving API endpoints processing Json Web Encryption messages. Impacts: Thank you, to hkario for
    reporting this vulnerability and thank you Michael Dawson for fixing it. (CVE-2023-46809)

  - The Node.js Permission Model does not clarify in the documentation that wildcards should be only used as
    the last character of a file path. For example: ``` --allow-fs-read=/home/node/.ssh/*.pub ``` will ignore
    `pub` and give access to everything after `.ssh/`. This misleading documentation affects all users using
    the experimental permission model in Node.js 20 and Node.js 21. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. (CVE-2024-21890)

  - Node.js depends on multiple built-in utility functions to normalize paths provided to node:fs functions,
    which can be overwitten with user-defined implementations leading to filesystem permission model bypass
    through path traversal attack. This vulnerability affects all users using the experimental permission
    model in Node.js 20 and Node.js 21. Please note that at the time this CVE was issued, the permission model
    is an experimental feature of Node.js. (CVE-2024-21891)

  - On Linux, Node.js ignores certain environment variables if those may have been set by an unprivileged user
    while the process is running with elevated privileges with the only exception of CAP_NET_BIND_SERVICE. Due
    to a bug in the implementation of this exception, Node.js incorrectly applies this exception even when
    certain other capabilities have been set. This allows unprivileged users to inject code that inherits the
    process's elevated privileges. (CVE-2024-21892)

  - The permission model protects itself against path traversal attacks by calling path.resolve() on any paths
    given by the user. If the path is to be treated as a Buffer, the implementation uses Buffer.from() to
    obtain a Buffer from the result of path.resolve(). By monkey-patching Buffer internals, namely,
    Buffer.prototype.utf8Write, the application can modify the result of path.resolve(), which leads to a path
    traversal vulnerability. This vulnerability affects all users using the experimental permission model in
    Node.js 20 and Node.js 21. Please note that at the time this CVE was issued, the permission model is an
    experimental feature of Node.js. (CVE-2024-21896)

  - setuid() does not affect libuv's internal io_uring operations if initialized before the call to setuid().
    This allows the process to perform privileged operations despite presumably having dropped such privileges
    through a call to setuid(). Impacts: Thank you, to valette for reporting this vulnerability and thank you
    Tobias Nieen for fixing it. (CVE-2024-22017)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220017");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/018059.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b34a69fc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24806");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21896");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs20-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs20-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-devel-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-docs-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'npm20-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs20-devel-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs20-docs-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'npm20-20.11.1-150500.11.6.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'corepack20-20.11.1-150500.11.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-20.11.1-150500.11.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-devel-20.11.1-150500.11.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-docs-20.11.1-150500.11.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'npm20-20.11.1-150500.11.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'corepack20 / nodejs20 / nodejs20-devel / nodejs20-docs / npm20');
}
