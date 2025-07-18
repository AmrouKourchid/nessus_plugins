#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1064.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138988);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/28");

  script_cve_id(
    "CVE-2020-13753",
    "CVE-2020-9802",
    "CVE-2020-9803",
    "CVE-2020-9805",
    "CVE-2020-9806",
    "CVE-2020-9807",
    "CVE-2020-9843",
    "CVE-2020-9850"
  );

  script_name(english:"openSUSE Security Update : webkit2gtk3 (openSUSE-2020-1064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for webkit2gtk3 fixes the following issues :

  - Update to version 2.28.3 (bsc#1173998) :

  + Enable kinetic scrolling with async scrolling.

  + Fix web process hangs on large GitHub pages.

  + Bubblewrap sandbox should not attempt to bind empty
    paths.

  + Fix threading issues in the media player.

  + Fix several crashes and rendering issues.

  + Security fixes: CVE-2020-9802, CVE-2020-9803,
    CVE-2020-9805, CVE-2020-9806, CVE-2020-9807,
    CVE-2020-9843, CVE-2020-9850, CVE-2020-13753.

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173998");
  script_set_attribute(attribute:"solution", value:
"Update the affected webkit2gtk3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9850");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari in Operator Side Effect Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjavascriptcoregtk-4_0-18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk-4_0-37-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit2gtk3-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-JavaScriptCore-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-WebKit2WebExtension-4_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk-4_0-injected-bundles-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit2gtk3-minibrowser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"libjavascriptcoregtk-4_0-18-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libjavascriptcoregtk-4_0-18-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwebkit2gtk-4_0-37-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwebkit2gtk-4_0-37-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwebkit2gtk3-lang-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-JavaScriptCore-4_0-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-WebKit2-4_0-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-WebKit2WebExtension-4_0-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit-jsc-4-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit-jsc-4-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk-4_0-injected-bundles-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk-4_0-injected-bundles-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk3-debugsource-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk3-devel-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk3-minibrowser-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"webkit2gtk3-minibrowser-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libjavascriptcoregtk-4_0-18-32bit-debuginfo-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-2.28.3-lp151.2.21.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwebkit2gtk-4_0-37-32bit-debuginfo-2.28.3-lp151.2.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjavascriptcoregtk-4_0-18 / libjavascriptcoregtk-4_0-18-debuginfo / etc");
}
