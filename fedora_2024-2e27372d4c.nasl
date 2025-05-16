#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-2e27372d4c
#

include('compat.inc');

if (description)
{
  script_id(200103);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2024-36048");
  script_xref(name:"FEDORA", value:"2024-2e27372d4c");

  script_name(english:"Fedora 40 : deepin-qt5integration / deepin-qt5platform-plugins / dwayland / etc (2024-2e27372d4c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2024-2e27372d4c advisory.

    Qt 5.15.14 bugfix update.

    ----

    Fix CVE-2024-36048

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2e27372d4c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:deepin-qt5integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:deepin-qt5platform-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fcitx-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fcitx5-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gammaray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kddockwidgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:keepassxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-akonadi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-frameworkintegration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kf5-kwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:plasma-integration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qadwaitadecorations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qgnomeplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtcharts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtdatavis3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtgamepad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtnetworkauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtremoteobjects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtscxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtspeech");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtvirtualkeyboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtwebview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt5ct");
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
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'deepin-qt5integration-5.6.11-7.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'deepin-qt5platform-plugins-5.6.12-7.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dwayland-5.25.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fcitx-qt5-1.2.6-21.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'fcitx5-qt-5.1.6-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gammaray-3.0.0-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kddockwidgets-1.7.0-10.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'keepassxc-2.7.8-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kf5-akonadi-server-23.08.5-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kf5-frameworkintegration-5.115.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kf5-kwayland-5.115.0-3.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-integration-6.0.5-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-qt5-5.15.10-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qadwaitadecorations-0.1.5-4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qgnomeplatform-0.9.2-15.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcharts-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdatavis3d-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgamepad-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtnetworkauth-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtremoteobjects-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscxml-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtspeech-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtvirtualkeyboard-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebengine-5.15.16-6.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebkit-5.212.0-0.87alpha4.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebview-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.15.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5ct-1.1-24.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'deepin-qt5integration / deepin-qt5platform-plugins / dwayland / etc');
}
