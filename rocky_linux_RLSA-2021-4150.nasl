#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:4150.
##

include('compat.inc');

if (description)
{
  script_id(184505);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2021-20270", "CVE-2021-27291");
  script_xref(name:"RLSA", value:"2021:4150");

  script_name(english:"Rocky Linux 8 : python36:3.6 (RLSA-2021:4150)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:4150 advisory.

  - An infinite loop in SMLLexer in Pygments versions 1.5 to 2.7.3 may lead to denial of service when
    performing syntax highlighting of a Standard ML (SML) source file, as demonstrated by input that only
    contains the exception keyword. (CVE-2021-20270)

  - In pygments 1.1+, fixed in 2.7.4, the lexers used to parse programming languages rely heavily on regular
    expressions. Some of the regular expressions have exponential or cubic worst-case complexity and are
    vulnerable to ReDoS. By crafting malicious input, an attacker can cause a denial of service.
    (CVE-2021-27291)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:4150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1917971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1922136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1934199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1940603");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27291");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-pymongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-virtualenv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-bson-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pymongo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-scipy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python36-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:scipy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/python36');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python36:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python36:' + module_ver);

var appstreams = {
    'python36:3.6': [
      {'reference':'python-nose-docs-1.3.7-31.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-debugsource-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-doc-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-doc-3.7.0-1.module+el8.5.0+671+195e4563', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.3.0+120+426d8baf', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-2.module+el8.4.0+403+9ae17a31', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-virtualenv-doc-15.1.0-21.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-distro-1.4.0-2.module+el8.3.0+120+426d8baf', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docs-3.6.7-2.module+el8.3.0+120+426d8baf', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docs-3.6.7-2.module+el8.4.0+597+ddf0ddea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docutils-0.14-12.module+el8.3.0+120+426d8baf', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docutils-0.14-12.module+el8.4.0+597+ddf0ddea', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nose-1.3.7-31.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pygments-2.2.0-22.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-debuginfo-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-debuginfo-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.7.0-1.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.7.0-1.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-PyMySQL-0.10.1-2.module+el8.4.0+597+ddf0ddea', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-debuginfo-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-debuginfo-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.3.0+120+426d8baf', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.3.0+120+426d8baf', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.4.0+597+ddf0ddea', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-2.module+el8.4.0+597+ddf0ddea', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-virtualenv-15.1.0-21.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-wheel-0.31.1-3.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-wheel-wheel-0.31.1-3.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python36-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-debug-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-debug-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-devel-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-devel-3.6.8-38.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-rpm-macros-3.6.8-38.module+el8.5.0+671+195e4563', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'scipy-debugsource-1.0.0-21.module+el8.5.0+671+195e4563', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python36:3.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-nose-docs / python-pymongo-debuginfo / etc');
}
