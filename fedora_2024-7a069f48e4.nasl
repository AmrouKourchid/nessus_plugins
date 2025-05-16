#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-7a069f48e4
#

include('compat.inc');

if (description)
{
  script_id(211212);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2015-2104",
    "CVE-2023-27043",
    "CVE-2024-4030",
    "CVE-2024-4032",
    "CVE-2024-6232",
    "CVE-2024-6923",
    "CVE-2024-7592",
    "CVE-2024-8088",
    "CVE-2024-28757",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492"
  );
  script_xref(name:"FEDORA", value:"2024-7a069f48e4");

  script_name(english:"Fedora 41 : python3.8 (2024-7a069f48e4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 41 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-7a069f48e4 advisory.

    This is a security release of Python 3.11
    -----------------------------------------

    **Note:** The release you're looking at is Python 3.11.10, a **security bugfix release** for the legacy
    3.11 series. *Python 3.12* is now the latest feature release series of Python 3.

    Security content in this release
    --------------------------------

    -   [gh-123067](https://github.com/python/cpython/issues/123067): Fix quadratic complexity in parsing
    ``-quoted cookie values with backslashes by
    [`http.cookies`](https://docs.python.org/3/library/http.cookies.html#module-http.cookies). Fixes
    CVE-2024-7592.
    -   [gh-113171](https://github.com/python/cpython/issues/113171): Fixed various false positives and false
    negatives in IPv4Address.is_private, IPv4Address.is_global, IPv6Address.is_private, IPv6Address.is_global.
    Fixes CVE-2024-4032.
    -   [gh-67693](https://github.com/python/cpython/issues/67693): Fix
    [`urllib.parse.urlunparse()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunparse)
    and
    [`urllib.parse.urlunsplit()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunsplit)
    for URIs with path starting with multiple slashes and no authority. Fixes CVE-2015-2104.
    -   [gh-121957](https://github.com/python/cpython/issues/121957): Fixed missing audit events around
    interactive use of Python, now also properly firing for `python -i`, as well as for `python -m asyncio`.
    The event in question is `cpython.run_stdin`.
    -   [gh-122133](https://github.com/python/cpython/issues/122133): Authenticate the socket connection for
    the `socket.socketpair()` fallback on platforms where `AF_UNIX` is not available like Windows.
    -   [gh-121285](https://github.com/python/cpython/issues/121285): Remove backtracking from tarfile header
    parsing for `hdrcharset`, PAX, and GNU sparse headers. That's CVE-2024-6232.
    -   [gh-114572](https://github.com/python/cpython/issues/114572): [`ssl.SSLContext.cert_store_stats()`](ht
    tps://docs.python.org/3/library/ssl.html#ssl.SSLContext.cert_store_stats) and
    [`ssl.SSLContext.get_ca_certs()`](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.get_ca_certs)
    now correctly lock access to the certificate store, when the
    [`ssl.SSLContext`](https://docs.python.org/3/library/ssl.html#ssl.SSLContext) is shared across multiple
    threads.
    -   [gh-102988](https://github.com/python/cpython/issues/102988): [`email.utils.getaddresses()`](https://d
    ocs.python.org/3/library/email.utils.html#email.utils.getaddresses) and
    [`email.utils.parseaddr()`](https://docs.python.org/3/library/email.utils.html#email.utils.parseaddr) now
    return `('', '')` 2-tuples in more situations where invalid email addresses are encountered instead of
    potentially inaccurate values. Add optional *strict* parameter to these two functions: use `strict=False`
    to get the old behavior, accept malformed inputs. `getattr(email.utils, 'supports_strict_parsing', False)`
    can be use to check if the *strict* paramater is available. This improves the CVE-2023-27043 fix.
    -   [gh-123270](https://github.com/python/cpython/issues/123270): Sanitize names in
    [`zipfile.Path`](https://docs.python.org/3/library/zipfile.html#zipfile.Path) to avoid infinite loops
    ([gh-122905](https://github.com/python/cpython/issues/122905)) without breaking contents using legitimate
    characters. That's CVE-2024-8088.
    -   [gh-121650](https://github.com/python/cpython/issues/121650):
    [`email`](https://docs.python.org/3/library/email.html#module-email) headers with embedded newlines are
    now quoted on output. The [`generator`](https://docs.python.org/3/library/email.generator.html#module-
    email.generator) will now refuse to serialize (write) headers that are unsafely folded or delimited; see [
    `verify_generated_headers`](https://docs.python.org/3/library/email.policy.html#email.policy.Policy.verify
    _generated_headers). That's CVE-2024-6923.
    -   [gh-119690](https://github.com/python/cpython/issues/119690): Fixes data type confusion in audit
    events raised by `_winapi.CreateFile` and `_winapi.CreateNamedPipe`.
    -   [gh-116773](https://github.com/python/cpython/issues/116773): Fix instances of
    `<_overlapped.Overlapped object at 0xXXX> still has pending operation at deallocation, the process may
    crash`.
    -   [gh-112275](https://github.com/python/cpython/issues/112275): A deadlock involving `pystate.c`'s
    `HEAD_LOCK` in `posixmodule.c` at fork is now fixed.This is a security release of Python 3.9
    ----------------------------------------

    **Note:** The release you're looking at is Python 3.9.20, a **security bugfix release** for the legacy 3.9
    series. *Python 3.12* is now the latest feature release series of Python 3. [Get the latest release of
    3.12.x here](https://www.python.org/downloads/).

    Security content in this release
    --------------------------------

    -   [gh-123678](https://github.com/python/cpython/issues/123678) and
    [gh-116741](https://github.com/python/cpython/issues/116741): Upgrade bundled libexpat to 2.6.3 to fix
    [CVE-2024-28757](https://github.com/advisories/GHSA-ch5v-h69f-mxc8),
    [CVE-2024-45490](https://github.com/advisories/GHSA-4hvh-m426-wv8w),
    [CVE-2024-45491](https://github.com/advisories/GHSA-784x-7qm2-gp97) and
    [CVE-2024-45492](https://github.com/advisories/GHSA-5qxm-qvmj-8v79).
    -   [gh-118486](https://github.com/python/cpython/issues/118486):
    [`os.mkdir()`](https://docs.python.org/3/library/os.html#os.mkdir) on Windows now accepts *mode* of
    `0o700` to restrict the new directory to the current user. This fixes CVE-2024-4030 affecting
    [`tempfile.mkdtemp()`](https://docs.python.org/3/library/tempfile.html#tempfile.mkdtemp) in scenarios
    where the base temporary directory is more permissive than the default.
    -   [gh-123067](https://github.com/python/cpython/issues/123067): Fix quadratic complexity in parsing
    ``-quoted cookie values with backslashes by
    [`http.cookies`](https://docs.python.org/3/library/http.cookies.html#module-http.cookies). Fixes
    CVE-2024-7592.
    -   [gh-113171](https://github.com/python/cpython/issues/113171): Fixed various false positives and false
    negatives in IPv4Address.is_private, IPv4Address.is_global, IPv6Address.is_private, IPv6Address.is_global.
    Fixes CVE-2024-4032.
    -   [gh-67693](https://github.com/python/cpython/issues/67693): Fix
    [`urllib.parse.urlunparse()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunparse)
    and
    [`urllib.parse.urlunsplit()`](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunsplit)
    for URIs with path starting with multiple slashes and no authority. Fixes CVE-2015-2104.
    -   [gh-121957](https://github.com/python/cpython/issues/121957): Fixed missing audit events around
    interactive use of Python, now also properly firing for `python -i`, as well as for `python -m asyncio`.
    The event in question is `cpython.run_stdin`.
    -   [gh-122133](https://github.com/python/cpython/issues/122133): Authenticate the socket connection for
    the `socket.socketpair()` fallback on platforms where `AF_UNIX` is not available like Windows.
    -   [gh-121285](https://github.com/python/cpython/issues/121285): Remove backtracking from tarfile header
    parsing for `hdrcharset`, PAX, and GNU sparse headers. That's CVE-2024-6232.
    -   [gh-114572](https://github.com/python/cpython/issues/114572): [`ssl.SSLContext.cert_store_stats()`](ht
    tps://docs.python.org/3/library/ssl.html#ssl.SSLContext.cert_store_stats) and
    [`ssl.SSLContext.get_ca_certs()`](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.get_ca_certs)
    now correctly lock access to the certificate store, when the
    [`ssl.SSLContext`](https://docs.python.org/3/library/ssl.html#ssl.SSLContext) is shared across multiple
    threads.
    -   [gh-102988](https://github.com/python/cpython/issues/102988): [`email.utils.getaddresses()`](https://d
    ocs.python.org/3/library/email.utils.html#email.utils.getaddresses) and
    [`email.utils.parseaddr()`](https://docs.python.org/3/library/email.utils.html#email.utils.parseaddr) now
    return `('', '')` 2-tuples in more situations where invalid email addresses are encountered instead of
    potentially inaccurate values. Add optional *strict* parameter to these two functions: use `strict=False`
    to get the old behavior, accept malformed inputs. `getattr(email.utils, 'supports_strict_parsing', False)`
    can be use to check if the *strict* paramater is available. This improves the CVE-2023-27043 fix.
    -   [gh-123270](https://github.com/python/cpython/issues/123270): Sanitize names in
    [`zipfile.Path`](https://docs.python.org/3/library/zipfile.html#zipfile.Path) to avoid infinite loops
    ([gh-122905](https://github.com/python/cpython/issues/122905)) without breaking contents using legitimate
    characters. That's CVE-2024-8088.
    -   [gh-121650](https://github.com/python/cpython/issues/121650):
    [`email`](https://docs.python.org/3/library/email.html#module-email) headers with embedded newlines are
    now quoted on output. The [`generator`](https://docs.python.org/3/library/email.generator.html#module-
    email.generator) will now refuse to serialize (write) headers that are unsafely folded or delimited; see
    [`ver

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7a069f48e4");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3.8 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python3.8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^41([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 41', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'python3.8-3.8.20-1.fc41', 'release':'FC41', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3.8');
}
