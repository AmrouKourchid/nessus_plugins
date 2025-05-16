#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-f204e1d0ed
#

include('compat.inc');

if (description)
{
  script_id(211146);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-31628",
    "CVE-2022-31629",
    "CVE-2022-31630",
    "CVE-2022-37454"
  );
  script_xref(name:"IAVA", value:"2022-A-0397-S");
  script_xref(name:"IAVA", value:"2022-A-0455-S");
  script_xref(name:"IAVA", value:"2022-A-0515-S");
  script_xref(name:"FEDORA", value:"2022-f204e1d0ed");

  script_name(english:"Fedora 37 : php (2022-f204e1d0ed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-f204e1d0ed advisory.

    **PHP version 8.1.12** (27 Oct 2022)

    **Core:**

    * Fixes segfault with Fiber on FreeBSD i386 architecture. (David Carlier)

    **Fileinfo:**

    * Fixed bug [GH-8805](https://github.com/php/php-src/issues/8805) (finfo returns wrong mime type for
    woff/woff2 files). (Anatol)

    **GD:**

    * Fixed bug php#81739: OOB read due to insufficient input validation in imageloadfont().
    (**CVE-2022-31630**) (cmb)

    **Hash:**

    * Fixed bug php#81738: buffer overflow in hash_update() on long parameter. (**CVE-2022-37454**) (nicky at
    mouha dot be)

    **MBString:**

     - Fixed bug [GH-9683](https://github.com/php/php-src/issues/9683) (Problem when ISO-2022-JP-MS is
    specified in mb_ encode_mimeheader). (Alex Dowad)

    **Opcache:**

    * Added indirect call reduction for jit on x86 architectures. (wxue1)

    **Session:**

    * Fixed bug [GH-9583](https://github.com/php/php-src/issues/9583) (session_create_id() fails with user
    defined save handler that doesn't have a validateId() method). (Girgias)

    **Streams:**

    * Fixed bug [GH-9590](https://github.com/php/php-src/issues/9590) (stream_select does not abort upon
    exception or empty valid fd set). (Arnaud)

    ----

    **PHP version 8.1.11** (29 Sep 2022)

    **Core:**

    * Fixed bug php#81726: phar wrapper: DOS when using quine gzip file. (**CVE-2022-31628**). (cmb)
    * Fixed bug php#81727: Don't mangle HTTP variable names that clash with ones that have a specific semantic
    meaning. (**CVE-2022-31629**). (Derick)
    * Fixed bug [GH-9323](https://github.com/php/php-src/issues/9323) (Crash in
    ZEND_RETURN/GC/zend_call_function) (Tim Starling)
    * Fixed bug [GH-9361](https://github.com/php/php-src/issues/9361) (Segmentation fault on script exit
    php#9379). (cmb, Christian Schneider)
    * Fixed bug [GH-9447](https://github.com/php/php-src/issues/9447) (Invalid class FQN emitted by AST dump
    for new and class constants in constant expressions). (ilutov)

    **DOM:**

    * Fixed bug php#79451 (DOMDocument->replaceChild on doctype causes double free). (Nathan Freeman)

    **FPM:**

    * Fixed bug [GH-8885](https://github.com/php/php-src/issues/8885) (FPM access.log with stderr begins to
    write logs to error_log after daemon reload). (Dmitry Menshikov)
    * Fixed bug php#77780 (Headers already sent... when previous connection was aborted). (Jakub Zelenka)

    **GMP**

    * Fixed bug [GH-9308](https://github.com/php/php-src/issues/9308) (GMP throws the wrong error when a GMP
    object is passed to gmp_init()). (Girgias)

    **Intl**

    * Fixed bug [GH-9421](https://github.com/php/php-src/issues/9421) (Incorrect argument number for
    ValueError in NumberFormatter). (Girgias)

    **PCRE:**

    * Fixed pcre.jit on Apple Silicon. (Niklas Keller)

    **PDO_PGSQL:**

    * Fixed bug [GH-9411](https://github.com/php/php-src/issues/9411) (PgSQL large object resource is
    incorrectly closed). (Yurunsoft)

    **Reflection:**

    * Fixed bug [GH-8932](https://github.com/php/php-src/issues/8932) (ReflectionFunction provides no way to
    get the called class of a Closure). (cmb, Nicolas Grekas)

    **Streams:**

    * Fixed bug [GH-9316](https://github.com/php/php-src/issues/9316) ($http_response_header is wrong for long
    status line). (cmb, timwolla)


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-f204e1d0ed");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37454");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
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
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.1.12-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE}
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
