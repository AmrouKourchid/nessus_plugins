#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2213.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(129463);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/22");

  script_cve_id(
    "CVE-2018-20860",
    "CVE-2018-20861",
    "CVE-2019-14382",
    "CVE-2019-14383"
  );

  script_name(english:"openSUSE Security Update : libopenmpt (openSUSE-2019-2213)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libopenmpt fixes the following issues :

Security issues fixed :

  - CVE-2018-20861: Fixed crash with certain malformed
    custom tunings in MPTM files (bsc#1143578).

  - CVE-2018-20860: Fixed crash with malformed MED files
    (bsc#1143581).

  - CVE-2019-14383: Fixed J2B that allows an assertion
    failure during file parsing with debug STLs
    (bsc#1143584).

  - CVE-2019-14382: Fixed DSM that allows an assertion
    failure during file parsing with debug STLs
    (bsc#1143582).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143584");
  script_set_attribute(attribute:"solution", value:
"Update the affected libopenmpt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmodplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenmpt_modplug1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openmpt123");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openmpt123-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libmodplug-devel-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmodplug1-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmodplug1-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt-debugsource-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt-devel-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt0-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt0-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt_modplug1-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopenmpt_modplug1-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openmpt123-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"openmpt123-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmodplug1-32bit-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libmodplug1-32bit-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenmpt0-32bit-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenmpt0-32bit-debuginfo-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenmpt_modplug1-32bit-0.3.17-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libopenmpt_modplug1-32bit-debuginfo-0.3.17-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmodplug-devel / libmodplug1 / libmodplug1-debuginfo / etc");
}
