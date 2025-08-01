#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0447-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(122344);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2018-15518", "CVE-2018-19873");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libqt5-qtbase (SUSE-SU-2019:0447-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libqt5-qtbase provides the following fixes :

Security issues fixed :

CVE-2018-15518: Fixed double free in QXmlStreamReader (bsc#1118595)

CVE-2018-19873: Fixed Denial of Service on malformed BMP file in
QBmpHandler (bsc#1118596)

Non-security issues fixed: Fix dynamic loading of libGL. (bsc#1099874)

Make sure printer settings are properly remembered. (bsc#1096328)

Add patch to fix fails to load pixmap cursors on XRender less system
(bsc#1108889)

Fix krita pop-up palette not working properly (bsc#1120639)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1108889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1118595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1118596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15518/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19873/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190447-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56633ed1");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-447=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-447=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-447=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5KmsSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5OpenGLExtensions-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PlatformHeaders-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PlatformSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-common-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-platformtheme-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqt5-qtbase-platformtheme-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Bootstrap-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Concurrent-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Concurrent5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Concurrent5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Core-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Core5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Core5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5DBus-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5DBus-devel-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5DBus5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5DBus5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Gui-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Gui5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Gui5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5KmsSupport-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Network-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Network5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Network5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5OpenGL-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5OpenGL5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5OpenGL5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5OpenGLExtensions-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5PlatformHeaders-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5PlatformSupport-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5PrintSupport-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5PrintSupport5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5PrintSupport5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-mysql-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-mysql-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-postgresql-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-postgresql-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-sqlite-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-sqlite-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-unixODBC-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Sql5-unixODBC-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Test-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Test5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Test5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Widgets-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Widgets5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Widgets5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Xml-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Xml5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libQt5Xml5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-common-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-common-devel-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-debugsource-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-examples-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-examples-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-platformtheme-gtk3-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libqt5-qtbase-platformtheme-gtk3-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Bootstrap-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Concurrent-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Concurrent5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Concurrent5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Core-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Core5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Core5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5DBus-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5DBus-devel-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5DBus5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5DBus5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Gui-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Gui5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Gui5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5KmsSupport-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Network-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Network5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Network5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5OpenGL-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5OpenGL5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5OpenGL5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5OpenGLExtensions-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5PlatformHeaders-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5PlatformSupport-devel-static-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5PrintSupport-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5PrintSupport5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5PrintSupport5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-mysql-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-mysql-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-postgresql-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-postgresql-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-sqlite-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-sqlite-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-unixODBC-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Sql5-unixODBC-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Test-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Test5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Test5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Widgets-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Widgets5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Widgets5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Xml-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Xml5-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libQt5Xml5-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-common-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-common-devel-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-debugsource-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-devel-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-examples-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-examples-debuginfo-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-platformtheme-gtk3-5.9.4-8.11.13")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libqt5-qtbase-platformtheme-gtk3-debuginfo-5.9.4-8.11.13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqt5-qtbase");
}
