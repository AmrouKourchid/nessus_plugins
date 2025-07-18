#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2292.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145313);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id("CVE-2020-16121");

  script_name(english:"openSUSE Security Update : PackageKit (openSUSE-2020-2292)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for PackageKit fixes the following issue :

  - CVE-2020-16121: Fixed an Information disclosure in
    InstallFiles, GetFilesLocal and GetDetailsLocal
    (bsc#1176930).

  - Notify service manager when it shutdown and cleanup
    temporary files when PackageKit quits. (bsc#1169739)

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176930");
  script_set_attribute(attribute:"solution", value:
"Update the affected PackageKit packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16121");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-backend-zypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gstreamer-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-gtk3-module-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:PackageKit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpackagekit-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-PackageKitGlib-1_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-backend-zypp-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-backend-zypp-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-branding-upstream-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-debugsource-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-devel-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-devel-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-gstreamer-plugin-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-gstreamer-plugin-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-gtk3-module-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-gtk3-module-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"PackageKit-lang-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpackagekit-glib2-18-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpackagekit-glib2-18-debuginfo-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpackagekit-glib2-devel-1.1.10-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-PackageKitGlib-1_0-1.1.10-lp151.8.12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-backend-zypp / etc");
}
