#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-27.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145310);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id("CVE-2017-17784", "CVE-2017-17785", "CVE-2017-17786");

  script_name(english:"openSUSE Security Update : gimp (openSUSE-2021-27)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for gimp fixes the following issues :

  - CVE-2017-17784: Fixed an insufficient string validation
    for input names (bsc#1073624).

  - CVE-2017-17785: Fixed an heap-based buffer overflow in
    FLI import (bsc#1073625).

  - CVE-2017-17786: Fixed an out-of-bounds read in TGA
    (bsc#1073626).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073626");
  script_set_attribute(attribute:"solution", value:
"Update the affected gimp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugin-aa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gimp-plugins-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimp-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpui-2_0-0-debuginfo");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"gimp-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-debugsource-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-devel-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-devel-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-lang-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-plugin-aa-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-plugin-aa-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-plugins-python-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gimp-plugins-python-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgimp-2_0-0-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgimp-2_0-0-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgimpui-2_0-0-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libgimpui-2_0-0-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgimp-2_0-0-32bit-debuginfo-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-2.8.22-lp151.5.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libgimpui-2_0-0-32bit-debuginfo-2.8.22-lp151.5.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-debuginfo / gimp-debugsource / gimp-devel / etc");
}
