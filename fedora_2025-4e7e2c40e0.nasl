#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2025-4e7e2c40e0
#

include('compat.inc');

if (description)
{
  script_id(233171);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-11235",
    "CVE-2025-1217",
    "CVE-2025-1219",
    "CVE-2025-1734",
    "CVE-2025-1736",
    "CVE-2025-1861"
  );
  script_xref(name:"IAVA", value:"2025-A-0183");
  script_xref(name:"FEDORA", value:"2025-4e7e2c40e0");

  script_name(english:"Fedora 40 : php (2025-4e7e2c40e0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2025-4e7e2c40e0 advisory.

    **PHP version 8.3.19** (13 Mar 2025)

    **BCMath:**

    * Fixed bug [GH-17398](https://github.com/php/php-src/issues/17398) (bcmul memory leak). (SakiTakamachi)

    **Core:**

    * Fixed bug [GH-17623](https://github.com/php/php-src/issues/17623) (Broken stack overflow detection for
    variable compilation). (ilutov)
    * Fixed bug [GH-17618](https://github.com/php/php-src/issues/17618) (UnhandledMatchError does not take
    zend.exception_ignore_args=1 into account). (timwolla)
    * Fix fallback paths in fast_long_{add,sub}_function. (nielsdos)
    * Fixed bug [GH-17718](https://github.com/php/php-src/issues/17718) (Calling static methods on an
    interface that has `__callStatic` is allowed). (timwolla)
    * Fixed bug [GH-17797](https://github.com/php/php-src/issues/17797) (zend_test_compile_string crash on
    invalid script path). (David Carlier)
    * Fixed [GHSA-rwp7-7vc6-8477](https://github.com/php/php-src/security/advisories/GHSA-rwp7-7vc6-8477)
    (Reference counting in php_request_shutdown causes Use-After-Free). (**CVE-2024-11235**) (ilutov)

    **DOM:**

    * Fixed bug [GH-17847](https://github.com/php/php-src/issues/17847) (xinclude destroys live node).
    (nielsdos)

    **FFI:**

    * Fix FFI Parsing of Pointer Declaration Lists. (davnotdev)

    **FPM:**

    * Fixed bug [GH-17643](https://github.com/php/php-src/issues/17643) (FPM with httpd ProxyPass encoded
    PATH_INFO env). (Jakub Zelenka)

    **GD:**

    * Fixed bug [GH-17772](https://github.com/php/php-src/issues/17772) (imagepalettetotruecolor crash with
    memory_limit=2M). (David Carlier)

    **LDAP:**

    * Fixed bug [GH-17704](https://github.com/php/php-src/issues/17704) (ldap_search fails when $attributes
    contains a non-packed array with numerical keys). (nielsdos, 7u83)

    **LibXML:**

    * Fixed [GHSA-wg4p-4hqh-c3g9](https://github.com/php/php-src/security/advisories/GHSA-wg4p-4hqh-c3g9)
    (Reocurrence of php#72714). (nielsdos)
    * Fixed [GHSA-p3x9-6h7p-cgfc](https://github.com/php/php-src/security/advisories/GHSA-p3x9-6h7p-cgfc)
    (libxml streams use wrong `content-type` header when requesting a redirected resource).
    (**CVE-2025-1219**) (timwolla)

    **MBString:**

    * Fixed bug [GH-17503](https://github.com/php/php-src/issues/17503) (Undefined float conversion in
    mb_convert_variables). (cmb)

    **Opcache:**

    * Fixed bug [GH-17654](https://github.com/php/php-src/issues/17654) (Multiple classes using same trait
    causes function JIT crash). (nielsdos)
    * Fixed bug [GH-17577](https://github.com/php/php-src/issues/17577) (JIT packed type guard crash).
    (nielsdos, Dmitry)
    * Fixed bug [GH-17899](https://github.com/php/php-src/issues/17899) (zend_test_compile_string with invalid
    path when opcache is enabled). (David Carlier)
    * Fixed bug [GH-17868](https://github.com/php/php-src/issues/17868) (Cannot allocate memory with tracing
    JIT). (nielsdos)

    **PDO_SQLite:**

    * Fixed [GH-17837](https://github.com/php/php-src/issues/17837) ()::getColumnMeta() on unexecuted
    statement segfaults). (cmb)
    * Fix cycle leak in sqlite3 setAuthorizer(). (nielsdos)

    **Phar:**

    * Fixed bug [GH-17808](https://github.com/php/php-src/issues/17808): PharFileInfo refcount bug. (nielsdos)

    **PHPDBG:**

    * Partially fixed bug [GH-17387](https://github.com/php/php-src/issues/17387) (Trivial crash in phpdbg
    lexer). (nielsdos)
    * Fix memory leak in phpdbg calling registered function. (nielsdos)

    **Reflection:**

    * Fixed bug [GH-15902](https://github.com/php/php-src/issues/15902) (Core dumped in
    ext/reflection/php_reflection.c). (DanielEScherzer)

    **Standard:**

    * Fixed bug php#72666 (stat cache clearing inconsistent between file:// paths and plain paths). (Jakub
    Zelenka)

    **Streams:**

    * Fixed bug [GH-17650](https://github.com/php/php-src/issues/17650) (realloc with size 0 in
    user_filters.c). (nielsdos)
    * Fix memory leak on overflow in _php_stream_scandir(). (nielsdos)
    * Fixed [GHSA-hgf54-96fm-v528](https://github.com/php/php-src/security/advisories/GHSA-hgf54-96fm-v528)
    (Stream HTTP wrapper header check might omit basic auth header). (**CVE-2025-1736**) (Jakub Zelenka)
    * Fixed [GHSA-52jp-hrpf-2jff](https://github.com/php/php-src/security/advisories/GHSA-52jp-hrpf-2jff)
    (Stream HTTP wrapper truncate redirect location to 1024 bytes). (**CVE-2025-1861**) (Jakub Zelenka)
    * Fixed [GHSA-pcmh-g36c-qc44](https://github.com/php/php-src/security/advisories/GHSA-pcmh-g36c-qc44)
    (Streams HTTP wrapper does not fail for headers without colon). (**CVE-2025-1734**) (Jakub Zelenka)
    * Fixed [GHSA-v8xr-gpvj-cx9g](https://github.com/php/php-src/security/advisories/GHSA-v8xr-gpvj-cx9g)
    (Header parser of `http` stream wrapper does not handle folded headers). (**CVE-2025-1217**) (Jakub
    Zelenka)

    **Zlib:**

    * Fixed bug [GH-17745](https://github.com/php/php-src/issues/17745) (zlib extension incorrectly handles
    object arguments). (nielsdos)
    * Fix memory leak when encoding check fails. (nielsdos)
    * Fix zlib support for large files. (nielsdos)




Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4e7e2c40e0");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.3.19-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
