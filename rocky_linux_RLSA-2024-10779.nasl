#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:10779.
##

include('compat.inc');

if (description)
{
  script_id(213207);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2024-9287", "CVE-2024-11168");
  script_xref(name:"RLSA", value:"2024:10779");

  script_name(english:"RockyLinux 8 : python3:3.6.8 (RLSA-2024:10779)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:10779 advisory.

    * python: Virtual environment (venv) activation scripts don't quote paths (CVE-2024-9287)

    * python: Improper validation of IPv6 and IPvFuture addresses (CVE-2024-11168)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:10779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2321440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325776");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9287");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-11168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:platform-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:platform-python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:platform-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/python3');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python3:3.6.8');
if ('3.6.8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python3:' + module_ver);

var appstreams = {
    'python3:3.6.8': [
      {'reference':'platform-python-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-debug-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-debug-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-debug-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-devel-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-devel-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'platform-python-devel-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-debuginfo-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-debuginfo-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-debugsource-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-debugsource-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-debugsource-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-idle-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-idle-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-idle-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libs-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libs-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-libs-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-test-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-test-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-test-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-tkinter-3.6.8-69.el8_10.rocky.0', 'cpu':'aarch64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-tkinter-3.6.8-69.el8_10.rocky.0', 'cpu':'i686', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'python3-tkinter-3.6.8-69.el8_10.rocky.0', 'cpu':'x86_64', 'release':'8', 'el_string':'el8_10', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python3:3.6.8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'platform-python / platform-python-debug / platform-python-devel / etc');
}
