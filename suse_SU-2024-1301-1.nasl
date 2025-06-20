#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1301-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(193392);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/17");

  script_cve_id(
    "CVE-2024-24806",
    "CVE-2024-27982",
    "CVE-2024-27983",
    "CVE-2024-30260",
    "CVE-2024-30261"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1301-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : nodejs20 (SUSE-SU-2024:1301-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:1301-1 advisory.

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

  - The team has identified a vulnerability in the http server of the most recent version of Node, where
    malformed headers can lead to HTTP request smuggling. Specifically, if a space is placed before a content-
    length header, it is not interpreted correctly, enabling attackers to smuggle in a second request within
    the body of the first. Impacts: Thank you, to bpingel for reporting this vulnerability and Paolo Insogna
    for fixing it.  Summary The Node.js project will release new versions of the 18.x, 20.x, 21.x releases
    lines on or shortly after, Wednesday, April 3, 2024 in order to address: (CVE-2024-27982)

  - An attacker can make the Node.js HTTP/2 server completely unavailable by sending a small amount of HTTP/2
    frames packets with a few HTTP/2 frames inside. It is possible to leave some data in nghttp2 memory after
    reset when headers with HTTP/2 CONTINUATION frame are sent to the server and then a TCP connection is
    abruptly closed by the client triggering the Http2Session destructor while header frames are still being
    processed (and stored in memory) causing a race condition. (CVE-2024-27983)

  - Undici is an HTTP/1.1 client, written from scratch for Node.js. Undici cleared Authorization and Proxy-
    Authorization headers for `fetch()`, but did not clear them for `undici.request()`. This vulnerability was
    patched in version(s) 5.28.4 and 6.11.1. (CVE-2024-30260)

  - Undici is an HTTP/1.1 client, written from scratch for Node.js. An attacker can alter the `integrity`
    option passed to `fetch()`, allowing `fetch()` to accept requests as valid even if they have been
    tampered. This vulnerability was patched in version(s) 5.28.4 and 6.11.1. (CVE-2024-30261)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222603");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034986.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-30260");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-30261");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'nodejs20-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-devel-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-docs-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'npm20-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'nodejs20-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs20-devel-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'nodejs20-docs-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'npm20-20.12.1-150500.11.9.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-web-scripting-release-15.5', 'sles-release-15.5']},
    {'reference':'corepack20-20.12.1-150500.11.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-20.12.1-150500.11.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-devel-20.12.1-150500.11.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'nodejs20-docs-20.12.1-150500.11.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'npm20-20.12.1-150500.11.9.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
