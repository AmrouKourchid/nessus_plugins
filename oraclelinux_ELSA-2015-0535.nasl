#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:0535 and 
# Oracle Linux Security Advisory ELSA-2015-0535 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81807);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2014-7300");
  script_bugtraq_id(70178);
  script_xref(name:"RHSA", value:"2015:0535");

  script_name(english:"Oracle Linux 7 : GNOME / Shell (ELSA-2015-0535)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2015-0535 advisory.

    clutter
    [1.14.4-12]
    - Include upstream patch to prevent a crash when hitting hardware limits
      Resolves: rhbz#1115162

    [1.14.4-11]
    - Fix a typo in the Requires

    [1.14.4-10]
    - Add patch for quadbuffer stereo suppport
      Resolves: rhbz#1108891

    cogl
    [1.14.1-6]
    - Add patches for quadbuffer stereo suppport
      Resolves: rhbz#1108890

    [1.14.0-5.2]
    - Ensure the glBlitFramebuffer case is not hit for swrast, since that's
      still broken.

    gnome-shell
    [3.8.4-45]
    - Don't inform GDM about session changes that came from GDM
      Resolves: #1163474

    [3.8.4-44]
    - If password authentication is disabled and smartcard authentication is
      enabled and smartcard isn't plugged in at start up, prompt user for
      smartcard
      Resolves: #1159385

    [3.8.4-43]
    - Support long login banner messages more effectively
      Resolves: #1110036

    [3.8.4-42]
    - Respect disk-writes lockdown setting
      Resolves: rhbz#1154122

    [3.8.4-41]
    - Disallow consecutive screenshot requests to avoid an OOM situation
      Resolves: rhbz#1154107

    [3.8.4-41]
    - Add option to limit app switcher to current workspace
      Resolves: rhbz#1101568

    [3.8.4-40]
    - Try harder to use the default calendar application
      Resolves: rhbz#1052201

    [3.8.4-40]
    - Update workspace switcher fix
      Resolves: rhbz#1092102

    [3.8.4-39]
    - Validate screenshot parameters
      Resolves: rhbz#1104694

    [3.8.4-38]
    - Fix shrinking workspace switcher
      Resolves: rhbz#1092102

    [3.8.4-38]
    - Update fix for vertical monitor layouts to upstream fix
      Resolves: rhbz#1075240

    [3.8.4-38]
    - Fix traceback introduced in 3.8.4-36 when unlocking via
      user switcher
      Related: #1101333

    [3.8.4-37]
    - Fix problems with LDAP and disable-user-list=TRUE
      Resolves: rhbz#1137041

    [3.8.4-36]
    - Fix login screen focus issue following idle
      Resolves: rhbz#1101333

    [3.8.4-35]
    - Disallow cancel from login screen before login attempt
      has been initiated.
      Resolves: rhbz#1109530

    [3.8.4-34]
    - Disallow cancel from login screen after login is already
      commencing.
      Resolves: rhbz#1079294

    [3.8.4-33]
    - Add a patch for quadbuffer stereo suppport
      Resolves: rhbz#1108893

    mutter
    [3.8.4.16]
    - Fix window placement regression
      Resolves: rhbz#1153641

    [3.8.4-15]
    - Fix delayed mouse mode
      Resolves: rhbz#1149585

    [3.8.4-14]
    - Preserve window placement on monitor changes
      Resolves: rhbz#1126754

    [3.8.4-13]
    - Improve handling of vertical monitor layouts
      Resolves: rhbz#1108322

    [3.8.4-13]
    - Add patches for quadbuffer stereo suppport
      Fix a bad performance problem drawing window thumbnails
      Resolves: rhbz#861507

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-0535.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:clutter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cogl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnome-shell-browser-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutter-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'clutter-1.14.4-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-devel-1.14.4-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-doc-1.14.4-12.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-1.14.0-6.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-devel-1.14.0-6.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-doc-1.14.0-6.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.8.4-45.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-browser-plugin-3.8.4-45.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.8.4-16.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.8.4-16.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-1.14.4-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-devel-1.14.4-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clutter-doc-1.14.4-12.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-1.14.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-devel-1.14.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cogl-doc-1.14.0-6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-3.8.4-45.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gnome-shell-browser-plugin-3.8.4-45.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-3.8.4-16.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mutter-devel-3.8.4-16.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clutter / clutter-devel / clutter-doc / etc');
}
