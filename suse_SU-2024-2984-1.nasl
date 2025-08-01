#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2984-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205998);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id("CVE-2024-40724");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2984-1");
  script_xref(name:"IAVB", value:"2024-B-0121-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libqt5-qt3d (SUSE-SU-2024:2984-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has packages installed that are affected by a
vulnerability as referenced in the SUSE-SU-2024:2984-1 advisory.

    - CVE-2024-40724: Fixed a heap-based buffer overflow in the PLY importer class (bsc#1228204)
    - Checked for a nullptr returned from the shader manager
    - Fill image with transparency by default to avoid having junk if it's not filled properly before the
    first paint call
    - Fixed QTextureAtlas parenting that could lead to crashes due to being used after free'd

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228204");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036643.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40724");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DAnimation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DAnimation5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DCore-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DCore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DExtras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DExtras5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DInput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DInput5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DLogic-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DLogic5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuick5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickAnimation-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickAnimation5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickExtras-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickExtras5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickInput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickInput5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickRender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickRender5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickScene2D-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DQuickScene2D5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DRender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt53DRender5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qt3d-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qt3d-imports");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qt3d-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qt3d-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libQt53DAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DCore-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DCore-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DCore5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DCore5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DLogic-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DLogic-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DLogic5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DLogic5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuick-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuick-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuick5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuick5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickScene2D-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickScene2D-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickScene2D5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DQuickScene2D5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-imports-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-imports-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-private-headers-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-private-headers-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-tools-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libqt5-qt3d-tools-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'libQt53DAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DCore-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DCore-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DCore5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DCore5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DLogic-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DLogic-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DLogic5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DLogic5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuick-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuick-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuick5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuick5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickAnimation-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickAnimation5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickExtras-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickExtras5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickInput-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickInput5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickScene2D-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickScene2D-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickScene2D5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DQuickScene2D5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DRender-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libQt53DRender5-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-imports-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-imports-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-private-headers-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-private-headers-devel-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-tools-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'libqt5-qt3d-tools-5.15.12+kde0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-desktop-applications-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libQt53DAnimation-devel / libQt53DAnimation5 / libQt53DCore-devel / etc');
}
