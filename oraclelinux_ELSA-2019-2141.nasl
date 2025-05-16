#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-2141.
##

include('compat.inc');

if (description)
{
  script_id(180838);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2018-6790");

  script_name(english:"Oracle Linux 7 : kde-workspace (ELSA-2019-2141)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2019-2141 advisory.

    kdelibs
    [6:4.14.8-10]
    - Do not fork konsole process when opening terminal from apps using dolphin-part
      Resolves: bz#1710362

    [6:4.14.8-9]
    - Do not fork konsole process when opening terminal from apps using dolphin-part
      Resolves: bz#1710362

    [6:4.14.8-8]
    - Disable JAR repack script to avoid multilib regression
      Resolves: bz#1542864

    [6:4.14.8-7]
    - Handle case-sensitive mime types
      Resolves: bz#1542864

    kde-settings
    [19-23.9.0.1]
    - Change GreetString [bug 11710280]

    [19-23.9]
    - Check if we have write access to home directory before creating default folders
      Resolves: bz#1579764

    kde-workspace
    [4.11-19-13]
    - Sanitise notification HTML
      Resolves: bz#1568853

    - Increase cpu buffer size in ksysguard
      Resolves: bz#1611762

    kmag
    [4.10.5-4]
    - Make border around arrow cursor bright
      Resolves: bz#1619362

    virtuoso-opensource
    [1:6.1.6-7]
    - Fix URL
      Resolves: bz#1583962

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-2141.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6790");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kcm_colors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-settings-ksplash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-settings-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-settings-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-settings-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-workspace-ksplash-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kde-workspace-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdeclassic-cursor-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kdelibs-ktexteditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:khotkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:khotkeys-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kinfocenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ksysguard-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kwin-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kwin-gles-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kwin-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libkworkspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oxygen-cursor-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plasma-scriptengine-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:plasma-scriptengine-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virtuoso-opensource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:virtuoso-opensource-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
    {'reference':'kcm_colors-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-ksplash-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-minimal-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-plasma-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-pulseaudio-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-style-oxygen-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-devel-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-ksplash-themes-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-libs-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdeclassic-cursor-theme-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdelibs-4.14.8-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-apidocs-4.14.8-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-common-4.14.8-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-devel-4.14.8-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-ktexteditor-4.14.8-10.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kgreeter-plugins-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-libs-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kinfocenter-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmag-4.10.5-4.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmenuedit-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-libs-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguardd-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-libs-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-libs-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkworkspace-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oxygen-cursor-themes-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-python-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-ruby-4.11.19-13.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt-settings-19-23.9.0.1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-6.1.6-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virtuoso-opensource-utils-6.1.6-7.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'kde-style-oxygen-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-devel-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-ksplash-themes-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-libs-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdeclassic-cursor-theme-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdelibs-4.14.8-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-apidocs-4.14.8-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-common-4.14.8-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-devel-4.14.8-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-ktexteditor-4.14.8-10.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kgreeter-plugins-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-libs-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kinfocenter-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmag-4.10.5-4.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmenuedit-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-libs-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguardd-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-libs-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-libs-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkworkspace-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oxygen-cursor-themes-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-python-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-ruby-4.11.19-13.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt-settings-19-23.9.0.1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-6.1.6-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virtuoso-opensource-utils-6.1.6-7.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'kcm_colors-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-ksplash-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-minimal-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-plasma-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-settings-pulseaudio-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-style-oxygen-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-devel-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-ksplash-themes-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kde-workspace-libs-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdeclassic-cursor-theme-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kdelibs-4.14.8-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-apidocs-4.14.8-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-common-4.14.8-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-devel-4.14.8-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kdelibs-ktexteditor-4.14.8-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'6'},
    {'reference':'kgreeter-plugins-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'khotkeys-libs-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kinfocenter-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmag-4.10.5-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kmenuedit-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguard-libs-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ksysguardd-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-gles-libs-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kwin-libs-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkworkspace-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oxygen-cursor-themes-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-python-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'plasma-scriptengine-ruby-4.11.19-13.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt-settings-19-23.9.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'virtuoso-opensource-6.1.6-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'virtuoso-opensource-utils-6.1.6-7.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kcm_colors / kde-settings / kde-settings-ksplash / etc');
}
