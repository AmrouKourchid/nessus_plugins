#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-b46619f761
#

include('compat.inc');

if (description)
{
  script_id(193549);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-31629",
    "CVE-2024-1874",
    "CVE-2024-2756",
    "CVE-2024-3096"
  );
  script_xref(name:"IAVA", value:"2022-A-0397-S");
  script_xref(name:"FEDORA", value:"2024-b46619f761");
  script_xref(name:"IAVA", value:"2024-A-0244-S");

  script_name(english:"Fedora 39 : php (2024-b46619f761)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-b46619f761 advisory.

    **PHP version 8.2.18** (11 Apr 2024)

    **Core:**

    * Fixed bug [GH-13612](https://github.com/php/php-src/issues/13612) (Corrupted memory in destructor with
    weak references). (nielsdos)
    * Fixed bug [GH-13784](https://github.com/php/php-src/issues/13784) (AX_GCC_FUNC_ATTRIBUTE failure).
    (Remi)
    * Fixed bug [GH-13670](https://github.com/php/php-src/issues/13670) (GC does not scale well with a lot of
    objects created in destructor). (Arnaud)

    **DOM:**

    * Add some missing ZPP checks. (nielsdos)
    * Fix potential memory leak in XPath evaluation results. (nielsdos)
    * Fix phpdoc for DOMDocument load methods. (VincentLanglet)

    **FPM**

    * Fix incorrect check in fpm_shm_free(). (nielsdos)

    **GD:**

    * Fixed bug [GH-12019](https://github.com/php/php-src/issues/12019) (add GDLIB_CFLAGS in feature tests).
    (Michael Orlitzky)

    **Gettext:**

    * Fixed sigabrt raised with dcgettext/dcngettext calls with gettext 0.22.5 with category set to LC_ALL.
    (David Carlier)

    **MySQLnd:**

    * Fix [GH-13452](https://github.com/php/php-src/issues/13452) (Fixed handshake response [mysqlnd]). (Saki
    Takamachi)
    * Fix incorrect charset length in check_mb_eucjpms(). (nielsdos)

    **Opcache:**

    * Fixed [GH-13508](https://github.com/php/php-src/issues/13508) (JITed QM_ASSIGN may be optimized out when
    op1 is null). (Arnaud, Dmitry)
    * Fixed [GH-13712](https://github.com/php/php-src/issues/13712) (Segmentation fault for enabled observers
    when calling trait method of internal trait when opcache is loaded). (Bob)

    **PDO:**

    * Fix various PDORow bugs. (Girgias)

    **Random:**

    * Fixed bug [GH-13544](https://github.com/php/php-src/issues/13544) (Pre-PHP 8.2 compatibility for
    mt_srand with unknown modes). (timwolla)
    * Fixed bug [GH-13690](https://github.com/php/php-src/issues/13690) (Global Mt19937 is not properly reset
    in-between requests when MT_RAND_PHP is used). (timwolla)

    **Session:**

    * Fixed bug [GH-13680](https://github.com/php/php-src/issues/13680) (Segfault with session_decode and
    compilation error). (nielsdos)

    **Sockets:**

    * Fixed bug [GH-13604](https://github.com/php/php-src/issues/13604) (socket_getsockname returns random
    characters in the end of the socket name). (David Carlier)

    **SPL:**

    * Fixed bug [GH-13531](https://github.com/php/php-src/issues/13531) (Unable to resize SplfixedArray after
    being unserialized in PHP 8.2.15). (nielsdos)
    * Fixed bug [GH-13685](https://github.com/php/php-src/issues/13685) (Unexpected null pointer in
    zend_string.h). (nielsdos)

    **Standard:**

    * Fixed bug [GH-11808](https://github.com/php/php-src/issues/11808) (Live filesystem modified by tests).
    (nielsdos)
    * Fixed [GH-13402](https://github.com/php/php-src/issues/13402) (Added validation of `\n` in
    $additional_headers of mail()). (SakiTakamachi)
    * Fixed bug [GH-13203](https://github.com/php/php-src/issues/13203) (file_put_contents fail on strings
    over 4GB on Windows). (divinity76)
    * Fixed bug [GHSA-pc52-254m-w9w7](https://github.com/php/php-src/security/advisories/GHSA-pc52-254m-w9w7)
    (Command injection via array-ish $command parameter of proc_open). (CVE-2024-1874) (Jakub Zelenka)
    * Fixed bug [GHSA-wpj3-hf5j-x4v4](https://github.com/php/php-src/security/advisories/GHSA-wpj3-hf5j-x4v4)
    (__Host-/__Secure- cookie bypass due to partial CVE-2022-31629 fix). (**CVE-2024-2756**) (nielsdos)
    * Fixed bug [GHSA-h746-cjrr-wfmr](https://github.com/php/php-src/security/advisories/GHSA-h746-cjrr-wfmr)
    (password_verify can erroneously return true, opening ATO risk). (**CVE-2024-3096**) (Jakub Zelenka)

    **XML:**

    * Fixed bug [GH-13517](https://github.com/php/php-src/issues/13517) (Multiple test failures when building
    with --with-expat). (nielsdos)


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-b46619f761");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.2.18-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
