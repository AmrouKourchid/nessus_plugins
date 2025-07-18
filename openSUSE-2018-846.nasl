#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-846.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111627);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id("CVE-2015-4491");

  script_name(english:"openSUSE Security Update : gdk-pixbuf (openSUSE-2018-846)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for gdk-pixbuf fixes the following issues :

Security issue fixed :

  - CVE-2015-4491: Fix integer multiplication overflow that
    allows for DoS or potentially RCE (bsc#1053417).

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053417");
  script_set_attribute(attribute:"solution", value:
"Update the affected gdk-pixbuf packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-query-loaders-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgdk_pixbuf-2_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GdkPixbuf-2_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-debugsource-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-devel-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-devel-debuginfo-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-lang-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-query-loaders-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"gdk-pixbuf-query-loaders-debuginfo-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgdk_pixbuf-2_0-0-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgdk_pixbuf-2_0-0-debuginfo-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-GdkPixbuf-2_0-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-devel-32bit-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-devel-debuginfo-32bit-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-32bit-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"gdk-pixbuf-query-loaders-debuginfo-32bit-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-32bit-2.34.0-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgdk_pixbuf-2_0-0-debuginfo-32bit-2.34.0-19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-debugsource / gdk-pixbuf-devel / gdk-pixbuf-devel-32bit / etc");
}
