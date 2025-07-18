#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1239.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124189);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2018-19870", "CVE-2018-19872");

  script_name(english:"openSUSE Security Update : libqt5-qtbase (openSUSE-2019-1239)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libqt5-qtbase fixes the following issues :

Security issues fixed:&#9; 

  - CVE-2018-19872: Fixed an issue which could allow a
    division by zero leading to crash (bsc#1130246).

  - CVE-2018-19870: Fixed an improper check in QImage
    allocation which could allow Denial of Service when
    opening crafted gif files (bsc#1118597). Other issue
    addressed :

  - Fixed an issue which showing remote locations was not
    allowed (bsc#1129662).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1129662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130246");
  script_set_attribute(attribute:"solution", value:
"Update the affected libqt5-qtbase packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19870");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Bootstrap-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Concurrent5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Core5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5DBus5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Gui5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5KmsSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Network5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGL5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5OpenGLExtensions-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformHeaders-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PlatformSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5PrintSupport5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Sql5-unixODBC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Test5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Widgets5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libQt5Xml5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-common-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-platformtheme-gtk3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqt5-qtbase-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libQt5Bootstrap-devel-static-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Concurrent-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Concurrent5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Concurrent5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Core-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Core-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Core5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Core5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5DBus-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5DBus-devel-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5DBus-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5DBus5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5DBus5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Gui-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Gui-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Gui5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Gui5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5KmsSupport-devel-static-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5KmsSupport-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Network-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Network-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Network5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Network5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5OpenGL-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5OpenGL-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5OpenGL5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5OpenGL5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5OpenGLExtensions-devel-static-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PlatformHeaders-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PlatformSupport-devel-static-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PlatformSupport-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PrintSupport-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PrintSupport-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PrintSupport5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5PrintSupport5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-mysql-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-mysql-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-postgresql-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-postgresql-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-sqlite-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-sqlite-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-unixODBC-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Sql5-unixODBC-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Test-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Test-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Test5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Test5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Widgets-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Widgets-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Widgets5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Widgets5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Xml-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Xml5-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libQt5Xml5-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-common-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-common-devel-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-debugsource-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-examples-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-examples-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-platformtheme-gtk3-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-platformtheme-gtk3-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libqt5-qtbase-private-headers-devel-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Bootstrap-devel-static-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Concurrent-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Concurrent5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Core-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Core5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Core5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5DBus-devel-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5DBus5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5DBus5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Gui-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Gui5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Gui5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Network-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Network5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Network5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5OpenGL-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5OpenGL5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5OpenGLExtensions-devel-static-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5PlatformSupport-devel-static-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5PrintSupport-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5PrintSupport5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-mysql-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-postgresql-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-sqlite-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Sql5-unixODBC-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Test-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Test5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Test5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Widgets-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Widgets5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Widgets5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Xml-devel-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Xml5-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libQt5Xml5-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-5.9.4-lp150.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libqt5-qtbase-examples-32bit-debuginfo-5.9.4-lp150.11.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libQt5Bootstrap-devel-static / libQt5Concurrent-devel / etc");
}
