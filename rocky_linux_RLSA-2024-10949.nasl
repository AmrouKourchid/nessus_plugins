#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:10949.
##

include('compat.inc');

if (description)
{
  script_id(213228);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id(
    "CVE-2024-2756",
    "CVE-2024-3096",
    "CVE-2024-5458",
    "CVE-2024-8925",
    "CVE-2024-8927",
    "CVE-2024-9026"
  );
  script_xref(name:"RLSA", value:"2024:10949");

  script_name(english:"RockyLinux 9 : php:8.2 (RLSA-2024:10949)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:10949 advisory.

    * php: host/secure cookie bypass due to partial CVE-2022-31629 fix (CVE-2024-2756)

    * php: password_verify can erroneously return true, opening ATO risk (CVE-2024-3096)

    * php: Filter bypass in filter_var (FILTER_VALIDATE_URL) (CVE-2024-5458)

    * php: Erroneous parsing of multipart form data (CVE-2024-8925)

    * php: cgi.force_redirect configuration is bypassable due to the environment variable collision
    (CVE-2024-8927)

    * php: PHP-FPM Log Manipulation Vulnerability (CVE-2024-9026)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:10949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2317144");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-rrd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-xdebug3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.2');
if ('8.2' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:8.2': [
      {'reference':'apcu-panel-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debuginfo-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debuginfo-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debuginfo-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debuginfo-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debugsource-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debugsource-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debugsource-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-debugsource-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-apcu-devel-5.1.23-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debuginfo-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debuginfo-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debuginfo-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debuginfo-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debugsource-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debugsource-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debugsource-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-rrd-debugsource-2.0.3-4.module+el9.3.0+16050+d5cd6ed5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debuginfo-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debuginfo-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debuginfo-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debuginfo-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debugsource-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debugsource-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debugsource-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-xdebug3-debugsource-3.2.2-2.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debuginfo-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debuginfo-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debuginfo-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debuginfo-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debugsource-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debugsource-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debugsource-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'php-pecl-zip-debugsource-1.22.3-1.module+el9.4.0+20013+b017aa8e', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
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
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:8.2');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / php-pecl-apcu / php-pecl-apcu-debuginfo / etc');
}
