#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2227.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(129487);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/22");

  script_cve_id("CVE-2019-6446");

  script_name(english:"openSUSE Security Update : python-numpy (openSUSE-2019-2227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for python-numpy fixes the following issues :

Non-security issues fixed :

  - Updated to upstream version 1.16.1. (bsc#1149203)
    (jsc#SLE-8532)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149203");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-numpy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6446");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-numpy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-numpy_1_16_1-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-numpy_1_16_1-gnu-hpc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy_1_16_1-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy_1_16_1-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-numpy_1_16_1-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy-gnu-hpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy_1_16_1-gnu-hpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy_1_16_1-gnu-hpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-numpy_1_16_1-gnu-hpc-devel");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python-numpy-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-numpy-debugsource-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-numpy_1_16_1-gnu-hpc-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-numpy_1_16_1-gnu-hpc-debugsource-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy-devel-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy-gnu-hpc-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy-gnu-hpc-devel-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy_1_16_1-gnu-hpc-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy_1_16_1-gnu-hpc-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-numpy_1_16_1-gnu-hpc-devel-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy-devel-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy-gnu-hpc-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy-gnu-hpc-devel-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy_1_16_1-gnu-hpc-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy_1_16_1-gnu-hpc-debuginfo-1.16.1-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-numpy_1_16_1-gnu-hpc-devel-1.16.1-lp151.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-numpy_1_16_1-gnu-hpc-debuginfo / etc");
}
