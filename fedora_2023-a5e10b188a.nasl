#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-a5e10b188a
#

include('compat.inc');

if (description)
{
  script_id(185338);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-0927",
    "CVE-2023-0928",
    "CVE-2023-0929",
    "CVE-2023-0930",
    "CVE-2023-0931",
    "CVE-2023-0932",
    "CVE-2023-0933",
    "CVE-2023-0941",
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1217",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1223",
    "CVE-2023-1224",
    "CVE-2023-1225",
    "CVE-2023-1226",
    "CVE-2023-1227"
  );
  script_xref(name:"FEDORA", value:"2023-a5e10b188a");

  script_name(english:"Fedora 38 : alsa-plugins / attract-mode / audacious-plugins / blender / etc (2023-a5e10b188a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-a5e10b188a advisory.

    FFmpeg 6.0 upgrade.







    ----

    update to 111.0.5563.64. Fixes the following security issues:

    CVE-2023-0927 CVE-2023-0928 CVE-2023-0929 CVE-2023-0930 CVE-2023-0931 CVE-2023-0932 CVE-2023-0933
    CVE-2023-0941 CVE-2023-1213 CVE-2023-1214 CVE-2023-1215 CVE-2023-1216 CVE-2023-1217 CVE-2023-1218
    CVE-2023-1219 CVE-2023-1220 CVE-2023-1221 CVE-2023-1222 CVE-2023-1223 CVE-2023-1224 CVE-2023-1225
    CVE-2023-1226 CVE-2023-1227

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-a5e10b188a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1227");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:alsa-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:attract-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:audacious-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:celestia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromaprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ffmpegthumbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gstreamer1-plugin-libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:guacamole-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:haruna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:indi-3rdparty-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:indi-3rdparty-libraries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:k3b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kpipewire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kstars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libindi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:loudgain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mlt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mpv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:neatvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:notcurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nv-codec-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phd2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qmmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qmmp-plugin-pack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt6-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:qt6-qtwebengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:retroarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:siril");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:stellarium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:unpaper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wf-recorder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xine-lib");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'alsa-plugins-1.2.7.1-5.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'attract-mode-2.6.2-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'audacious-plugins-4.3-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'blender-3.4.1-16.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'celestia-1.7.0~20230305ebfcdb1-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromaprint-1.5.1-8.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-111.0.5563.64-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'ffmpeg-6.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ffmpegthumbs-22.12.3-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gstreamer1-plugin-libav-1.22.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'guacamole-server-1.5.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'haruna-0.10.3-3.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'indi-3rdparty-drivers-2.0.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'indi-3rdparty-libraries-2.0.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'k3b-22.12.3-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'kpipewire-5.27.2-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kstars-3.6.3-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libindi-2.0.0-3.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'loudgain-0.6.8-13.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mlt-7.14.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mpv-0.35.1-3.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'neatvnc-0.6.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'notcurses-3.0.8-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nv-codec-headers-12.0.16.0-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'phd2-2.6.11^dev4^20230212a205f63-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qmmp-2.1.2-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qmmp-plugin-pack-2.1.0-5.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt6-qtmultimedia-6.4.2-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt6-qtwebengine-6.4.2-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'retroarch-1.15.0-4.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'siril-1.0.6-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'stellarium-1.2-8.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'unpaper-7.0.0-7.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'wf-recorder-0.3.1-0.3.20221225gita9725f7.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xine-lib-1.2.13-1.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'alsa-plugins / attract-mode / audacious-plugins / blender / etc');
}
