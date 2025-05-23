#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-672.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110681);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/16");

  script_cve_id("CVE-2018-7187");

  script_name(english:"openSUSE Security Update : go1.9 (openSUSE-2018-672)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for go1.9 fixes the following issues :

Security issues fixed :

  - CVE-2018-7187: arbitrary command execution via VCS path
    (boo#1081495)

Non-security changes :

  - Update to version 1.9.7

  - fixes to the go command and compiler

  - minimal support to the go command for the vgo transition");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081495");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7187");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.9-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"go-1.9.7-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"go1.9-1.9.7-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"go-race-1.9.7-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"go1.9-race-1.9.7-lp150.2.4.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"go-1.9.7-37.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"go1.9-1.9.7-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"go-race-1.9.7-37.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"go1.9-race-1.9.7-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "go / go-race / go1.9 / go1.9-race");
}
