#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-274.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(134197);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_cve_id("CVE-2019-9674", "CVE-2020-8492");
  script_xref(name:"IAVA", value:"2020-A-0103-S");

  script_name(english:"openSUSE Security Update : python3 (openSUSE-2020-274)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for python3 fixes the following issues :

Security issues fixed :

  - CVE-2019-9674: Improved the documentation to reflect the
    dangers of zip-bombs (bsc#1162825).

  - CVE-2020-8492: Fixed a regular expression in urrlib that
    was prone to denial of service via HTTP (bsc#1162367).

Non-security issue fixed :

  - If the locale is 'C', coerce it to C.UTF-8
    (bsc#1162423).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162825");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8492");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9674");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE15.1", reference:"libpython3_6m1_0-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpython3_6m1_0-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-base-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-base-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-base-debugsource-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-curses-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-curses-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-dbm-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-dbm-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-debugsource-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-devel-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-devel-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-idle-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-testsuite-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-testsuite-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tk-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tk-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tools-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-32bit-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-32bit-debuginfo-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-base-32bit-3.6.10-lp151.6.11.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-base-32bit-debuginfo-3.6.10-lp151.6.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython3_6m1_0 / libpython3_6m1_0-debuginfo / python3-base / etc");
}
