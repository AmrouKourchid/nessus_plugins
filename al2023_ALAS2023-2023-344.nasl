#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2023-344.
##

include('compat.inc');

if (description)
{
  script_id(181703);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2023-30624",
    "CVE-2023-31124",
    "CVE-2023-31130",
    "CVE-2023-31147",
    "CVE-2023-32067",
    "CVE-2023-35941",
    "CVE-2023-35942",
    "CVE-2023-35943",
    "CVE-2023-35944"
  );

  script_name(english:"Amazon Linux 2023 : ecs-service-connect-agent (ALAS2023-2023-344)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2023-344 advisory.

    Wasmtime is a standalone runtime for WebAssembly. Prior to versions 6.0.2, 7.0.1, and 8.0.1, Wasmtime's
    implementation of managing per-instance state, such as tables and memories, contains LLVM-level undefined
    behavior. This undefined behavior was found to cause runtime-level issues when compiled with LLVM 16 which
    causes some writes, which are critical for correctness, to be optimized away. Vulnerable versions of
    Wasmtime compiled with Rust 1.70, which is currently in beta, or later are known to have incorrectly
    compiled functions. Versions of Wasmtime compiled with the current Rust stable release, 1.69, and prior
    are not known at this time to have any issues, but can theoretically exhibit potential issues.

    The underlying problem is that Wasmtime's runtime state for an instance involves a Rust-defined structure
    called `Instance` which has a trailing `VMContext` structure after it. This `VMContext` structure has a
    runtime-defined layout that is unique per-module. This representation cannot be expressed with safe code
    in Rust so `unsafe` code is required to maintain this state. The code doing this, however, has methods
    which take `&self` as an argument but modify data in the `VMContext` part of the allocation. This means
    that pointers derived from `&self` are mutated. This is typically not allowed, except in the presence of
    `UnsafeCell`, in Rust. When compiled to LLVM these functions have `noalias readonly` parameters which
    means it's UB to write through the pointers.

    Wasmtime's internal representation and management of `VMContext` has been updated to use `&mut self`
    methods where appropriate. Additionally verification tools for `unsafe` code in Rust, such as `cargo
    miri`, are planned to be executed on the `main` branch soon to fix any Rust-level issues that may be
    exploited in future compiler versions.

    Precomplied binaries available for Wasmtime from GitHub releases have been compiled with at most LLVM 15
    so are not known to be vulnerable. As mentioned above, however, it's still recommended to update.

    Wasmtime version 6.0.2, 7.0.1, and 8.0.1 have been issued which contain the patch necessary to work
    correctly on LLVM 16 and have no known UB on LLVM 15 and earlier. If Wasmtime is compiled with Rust 1.69
    and prior, which use LLVM 15, then there are no known issues. There is a theoretical possibility for
    undefined behavior to exploited, however, so it's recommended that users upgrade to a patched version of
    Wasmtime. Users using beta Rust (1.70 at this time) or nightly Rust (1.71 at this time) must update to a
    patched version to work correctly. (CVE-2023-30624)

    When cross-compiling c-ares and using the autotools build system, CARES_RANDOM_FILE will not be set, as
    seen when cross compiling aarch64 android. This will downgrade to using rand() as a fallback which could
    allow an attacker to take advantage of the lack of entropy by not using a CSPRNG. (CVE-2023-31124)

    ares_inet_net_pton() is vulnerable to a buffer underflow for certain ipv6 addresses, in particular
    0::00:00:00/2 was found to cause an issue. C-ares only uses this function internally for configuration
    purposes which would require an administrator to configure such an address via ares_set_sortlist().

    However, users may externally use ares_inet_net_pton() for other purposes and thus be vulnerable to more
    severe issues. (CVE-2023-31130)

    Insufficient randomness in generation of DNS query IDs

    When /dev/urandom or RtlGenRandom() are unavailable, c-ares uses rand() to generate random numbers used
    for DNS query ids. This is not a CSPRNG, and it is also not seeded by srand() so will generate predictable
    output.Input from the random number generator is fed into a non-compilant RC4 implementation and may not
    be as strong as the original RC4 implementation.No attempt is made to look for modern OS-provided CSPRNGs
    like arc4random() that is widely available. (CVE-2023-31147)

    Denial of Service.

    Attack Steps:

    The target resolver sends a queryThe attacker forges a malformed UDP packet with a length of 0 and returns
    them to the target resolverThe target resolver erroneously interprets the 0 length as a graceful shutdown
    of the connection. (this is only valid for TCP connections, UDP is connection-less)Current resolution
    fails, DoS attack is achieved. (CVE-2023-32067)

    Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.27.0, 1.26.4, 1.25.9, 1.24.10, and 1.23.12, a malicious client is able to construct credentials with
    permanent validity in some specific scenarios. This is caused by the some rare scenarios in which HMAC
    payload can be always valid in OAuth2 filter's check. Versions 1.27.0, 1.26.4, 1.25.9, 1.24.10, and
    1.23.12 have a fix for this issue. As a workaround, avoid wildcards/prefix domain wildcards in the host's
    domain configuration. (CVE-2023-35941)

    Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.27.0, 1.26.4, 1.25.9, 1.24.10, and 1.23.12, gRPC access loggers using listener's global scope can cause
    a `use-after-free` crash when the listener is drained. Versions 1.27.0, 1.26.4, 1.25.9, 1.24.10, and
    1.23.12 have a fix for this issue. As a workaround, disable gRPC access log or stop listener update.
    (CVE-2023-35942)

    Envoy is an open source edge and service proxy designed for cloud-native applications. Prior to versions
    1.27.0, 1.26.4, 1.25.9, 1.24.10, and 1.23.12, the CORS filter will segfault and crash Envoy when the
    `origin` header is removed and deleted between `decodeHeaders`and `encodeHeaders`. Versions 1.27.0,
    1.26.4, 1.25.9, 1.24.10, and 1.23.12 have a fix for this issue. As a workaround, do not remove the
    `origin` header in the Envoy configuration. (CVE-2023-35943)

    Envoy is an open source edge and service proxy designed for cloud-native applications. Envoy allows mixed-
    case schemes in HTTP/2, however, some internal scheme checks are case-sensitive. Prior to versions 1.27.0,
    1.26.4, 1.25.9, 1.24.10, and 1.23.12, this can lead to the rejection of requests with mixed-case schemes
    such as `htTp` or `htTps`, or the bypassing of some requests such as `https` in unencrypted connections.
    With a fix in versions 1.27.0, 1.26.4, 1.25.9, 1.24.10, and 1.23.12, Envoy will now lowercase scheme
    values by default, and change the internal scheme checks that were case-sensitive to be case-insensitive.
    There are no known workarounds for this issue. (CVE-2023-35944)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2023-344.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-30624.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31124.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31130.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-31147.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-32067.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-35941.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-35942.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-35943.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-35944.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update ecs-service-connect-agent --releasever 2023.2.20230920' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35941");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ecs-service-connect-agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'ecs-service-connect-agent-v1.27.0.0-1.amzn2023', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ecs-service-connect-agent-v1.27.0.0-1.amzn2023', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ecs-service-connect-agent");
}
