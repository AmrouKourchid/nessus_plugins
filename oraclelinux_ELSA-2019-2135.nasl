#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-2135.
##

include('compat.inc');

if (description)
{
  script_id(180876);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2018-15518",
    "CVE-2018-19869",
    "CVE-2018-19870",
    "CVE-2018-19871",
    "CVE-2018-19873"
  );

  script_name(english:"Oracle Linux 7 : qt5 (ELSA-2019-2135)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2019-2135 advisory.

    qt5-qt3d
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564024

    qt5-qtbase
    [5.9.7-1]
    - Enable -doc subpkg on PPC
      Resolves: bz#1564000

    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564000

    qt5-qtcanvas3d
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564001

    qt5-qtconnectivity
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564002

    qt5-qtdeclarative
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564003

    qt5-qtdoc
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564004

    qt5-qtgraphicaleffects
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564006

    qt5-qtimageformats
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564007

    qt5-qtlocation
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564008

    qt5-qtmultimedia
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564009

    qt5-qtquickcontrols2
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564011

    qt5-qtquickcontrols
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564010

    qt5-qtscript
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564012

    qt5-qtsensors
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564013

    qt5-qtserialbus
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564014

    qt5-qtserialport
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564015

    qt5-qtsvg
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564016

    qt5-qttools
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564017

    qt5-qttranslations
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564018

    qt5-qtwayland
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564019

    qt5-qtwebchannel
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564020

    qt5-qtwebsockets
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564021

    qt5-qtx11extras
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564023

    qt5-qtxmlpatterns
    [5.9.7-1]
    - Update to 5.9.7
      Resolves: bz#1564022

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2019-2135.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qt3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qt3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qt3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtcanvas3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtcanvas3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtcanvas3d-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtconnectivity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtconnectivity-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtconnectivity-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtconnectivity-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdeclarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdeclarative-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdeclarative-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdeclarative-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdeclarative-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtgraphicaleffects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtgraphicaleffects-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtimageformats");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtimageformats-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtlocation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtlocation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtlocation-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtlocation-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtmultimedia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtmultimedia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtmultimedia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtmultimedia-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtquickcontrols2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtscript-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsensors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsensors-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsensors-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialbus-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialport-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtserialport-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsvg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtsvg-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qttranslations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwayland-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwayland-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwayland-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebchannel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebchannel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebchannel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebchannel-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtwebsockets-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtx11extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtx11extras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtx11extras-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtxmlpatterns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtxmlpatterns-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtxmlpatterns-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-qtxmlpatterns-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt5-rpm-macros");
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
    {'reference':'qt5-assistant-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-designer-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-doctools-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-linguist-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qdbusviewer-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-static-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-common-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designer-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designercomponents-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-help-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-static-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-devel-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-doc-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-examples-5.9.7-1.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.9.7-2.el7', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-designer-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-doctools-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-linguist-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qdbusviewer-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-static-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-common-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designer-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designercomponents-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-help-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-static-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-devel-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-doc-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-examples-5.9.7-1.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.9.7-2.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-assistant-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-designer-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-doctools-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-linguist-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qdbusviewer-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qt3d-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-doc-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtcanvas3d-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtconnectivity-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdeclarative-static-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtdoc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtgraphicaleffects-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtimageformats-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtlocation-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtmultimedia-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtquickcontrols2-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtscript-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsensors-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialbus-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtserialport-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtsvg-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-common-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designer-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designercomponents-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-help-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-static-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttranslations-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwayland-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebchannel-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtwebsockets-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtx11extras-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-devel-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-doc-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtxmlpatterns-examples-5.9.7-1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-rpm-macros-5.9.7-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-assistant / qt5-designer / qt5-doctools / etc');
}
