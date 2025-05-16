#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-5732365005
#

include('compat.inc');

if (description)
{
  script_id(194718);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/13");

  script_cve_id("CVE-2022-31631");
  script_xref(name:"IAVA", value:"2023-A-0016-S");
  script_xref(name:"FEDORA", value:"2023-5732365005");

  script_name(english:"Fedora 37 : php (2023-5732365005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-5732365005 advisory.

    **PHP version 8.1.14** (05 Jan 2023)

    **Core:**

    * Fixed bug [GH-9905](https://github.com/php/php-src/issues/9905) (constant() behaves inconsistent when
    class is undefined). (cmb)
    * Fixed bug [GH-9918](https://github.com/php/php-src/issues/9918) (License information for xxHash is not
    included in README.REDIST.BINS file). (Akama Hitoshi)
    * Fixed bug [GH-9650](https://github.com/php/php-src/issues/9650) (Can't initialize heap: [0x000001e7]).
    (Michael Voek)
    * Fixed potentially undefined behavior in Windows ftok(3) emulation. (cmb)

    **Date:**

    * Fixed bug [GH-9699](https://github.com/php/php-src/issues/9699) (DateTimeImmutable::diff differences in
    8.1.10 onwards - timezone related). (Derick)
    * Fixed bug [GH-9700](https://github.com/php/php-src/issues/9700) (DateTime::createFromFormat: Parsing
    TZID string is too greedy). (Derick)
    * Fixed bug [GH-9866](https://github.com/php/php-src/issues/9866) (Time zone bug with
    \DateTimeInterface::diff()). (Derick)
    * Fixed bug [GH-9880](https://github.com/php/php-src/issues/9880) (DateTime diff returns wrong sign on day
    count when using a timezone). (Derick)

    **FPM:**

    * Fixed bug [GH-9959](https://github.com/php/php-src/issues/9959) (Solaris port event mechanism is still
    broken after bug php#66694). (Petr Sumbera)
    * Fixed bug php#68207 (Setting fastcgi.error_header can result in a WARNING). (Jakub Zelenka)
    * Fixed bug [GH-8517](https://github.com/php/php-src/issues/8517) (Random crash of FPM master process in
    fpm_stdio_child_said). (Jakub Zelenka)

    **MBString:**

    * Fixed bug [GH-9535](https://github.com/php/php-src/issues/9535) (The behavior of mb_strcut in mbstring
    has been changed in PHP8.1). (Nathan Freeman)

    **Opcache:**

    * Fixed bug [GH-9968](https://github.com/php/php-src/issues/9968) (Segmentation Fault during OPCache
    Preload). (Arnaud, michdingpayc)

    **OpenSSL:**

    * Fixed bug [GH-9064](https://github.com/php/php-src/issues/9064) (PHP fails to build if openssl was built
    with --no-ec). (Jakub Zelenka)
    * Fixed bug [GH-10000](https://github.com/php/php-src/issues/10000) (OpenSSL test failures when OpenSSL
    compiled with no-dsa). (Jakub Zelenka)

    **Pcntl:**

    * Fixed bug [GH-9298](https://github.com/php/php-src/issues/9298) (Signal handler called after rshutdown
    leads to crash). (Erki Aring)

    **PDO_Firebird:**

    * Fixed bug [GH-9971](https://github.com/php/php-src/issues/9971) (Incorrect NUMERIC value returned from
    PDO_Firebird). (cmb)

    **PDO/SQLite:**

    * Fixed bug php#81740 (PDO::quote() may return unquoted string). (**CVE-2022-31631**) (cmb)

    **Session:**

    * Fixed [GH-9932](https://github.com/php/php-src/issues/9932) (session name silently fails with . and [).
    (David Carlier)

    **SPL:**

    * Fixed [GH-9883](https://github.com/php/php-src/issues/9883) (SplFileObject::__toString() reads next
    line). (Girgias)
    * Fixed [GH-10011](https://github.com/php/php-src/issues/10011) (Trampoline autoloader will get
    reregistered and cannot be unregistered). (Girgias)

    **SQLite3:**

    * Fixed bug php#81742 (open_basedir bypass in SQLite3 by using file URI). (cmb)


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5732365005");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31631");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.1.14-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
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
