#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-781.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(137230);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/07");

  script_cve_id("CVE-2019-19956");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2020-781)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libxml2 fixes the following issues :

  - CVE-2019-19956: Reverted the upstream fix for this
    memory leak because it introduced other, more severe
    vulnerabilities (bsc#1172021).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172021");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libxml2-python-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"libxml2-2-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxml2-2-debuginfo-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxml2-debugsource-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxml2-devel-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxml2-tools-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libxml2-tools-debuginfo-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-libxml2-python-debugsource-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-libxml2-python-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-libxml2-python-debuginfo-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-libxml2-python-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-libxml2-python-debuginfo-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-lp151.5.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.7-lp151.5.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-debuginfo / libxml2-debugsource / etc");
}
