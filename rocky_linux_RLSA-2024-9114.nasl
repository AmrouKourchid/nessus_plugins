#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:9114.
##

include('compat.inc');

if (description)
{
  script_id(232912);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2024-36472");
  script_xref(name:"RLSA", value:"2024:9114");

  script_name(english:"RockyLinux 9 : gnome-shell and gnome-shell-extensions (RLSA-2024:9114)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:9114 advisory.

    * gnome-shell: code execution in portal helper (CVE-2024-36472)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:9114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2283750");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36472");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-classic-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-apps-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-auto-move-windows");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-classification-banner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-custom-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-dash-to-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-dash-to-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-drive-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-gesture-inhibitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-heads-up-display");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-launch-new-instance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-native-window-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-panel-favorites");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-places-menu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-screenshot-window-sizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-systemMonitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-top-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-updates-dialog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-user-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-window-list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-windowsNavigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extension-workspace-indicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:gnome-shell-extensions");
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
    {'reference':'gnome-classic-session-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-apps-menu-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-auto-move-windows-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-classification-banner-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-common-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-custom-menu-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-dash-to-dock-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-dash-to-panel-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-desktop-icons-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-drive-menu-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-gesture-inhibitor-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-heads-up-display-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-launch-new-instance-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-native-window-placement-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-panel-favorites-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-places-menu-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-screenshot-window-sizer-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-systemMonitor-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-top-icons-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-updates-dialog-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-user-theme-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-window-list-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-windowsNavigator-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'gnome-shell-extension-workspace-indicator-40.7-19.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gnome-classic-session / gnome-shell-extension-apps-menu / etc');
}
