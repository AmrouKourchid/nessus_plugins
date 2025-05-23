#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1752.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(126893);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/09");

  script_cve_id("CVE-2019-12779");

  script_name(english:"openSUSE Security Update : libqb (openSUSE-2019-1752)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libqb fixes the following issue :

Security issue fixed:&#9; 

  - CVE-2019-12779: Fixed an insecure treatment of IPC
    temporary files which could have allowed a local
    attacker to overwrite privileged system files
    (bsc#1137835).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137835");
  script_set_attribute(attribute:"solution", value:
"Update the affected libqb packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12779");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb20-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb20-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libqb20-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"libqb-debugsource-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb-devel-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb-tests-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb-tests-debuginfo-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb-tools-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb-tools-debuginfo-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb20-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libqb20-debuginfo-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libqb-devel-32bit-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libqb20-32bit-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libqb20-32bit-debuginfo-1.0.3+20190326.a521604-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libqb-debugsource / libqb-devel / libqb-tests / etc");
}
