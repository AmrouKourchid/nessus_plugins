#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3834.
##

include('compat.inc');

if (description)
{
  script_id(235519);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2022-48622");
  script_xref(name:"RLSA", value:"2024:3834");

  script_name(english:"RockyLinux 9 : gdk-pixbuf2 (RLSA-2024:3834)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:3834 advisory.

    * gdk-pixbuf2: heap memory corruption on gdk-pixbuf (CVE-2022-48622)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2260545");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48622");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gdk-pixbuf2-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var pkgs = [
    {'reference':'gdk-pixbuf2-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-2.42.6-4.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debuginfo-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debuginfo-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debuginfo-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debuginfo-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debugsource-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debugsource-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debugsource-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-debugsource-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-2.42.6-4.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-debuginfo-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-debuginfo-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-debuginfo-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-devel-debuginfo-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-2.42.6-4.el9_4', 'cpu':'i686', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-debuginfo-2.42.6-4.el9_4', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-debuginfo-2.42.6-4.el9_4', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-debuginfo-2.42.6-4.el9_4', 'cpu':'s390x', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gdk-pixbuf2-modules-debuginfo-2.42.6-4.el9_4', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdk-pixbuf2 / gdk-pixbuf2-debuginfo / gdk-pixbuf2-debugsource / etc');
}
