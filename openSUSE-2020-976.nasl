#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-976.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138744);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2020-8023");

  script_name(english:"openSUSE Security Update : openldap2 (openSUSE-2020-976)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openldap2 fixes the following issues :

  - CVE-2020-8023: Fixed a potential local privilege
    escalation from ldap to root when
    OPENLDAP_CONFIG_BACKEND='ldap' was used
    (bsc#1172698).&#9; 

  - Changed DB_CONFIG to root:ldap permissions
    (bsc#1172704).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172704");
  script_set_attribute(attribute:"solution", value:
"Update the affected openldap2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-2_4-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldap-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-meta-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-back-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-ppolicy-check-password");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openldap2-ppolicy-check-password-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libldap-2_4-2-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldap-2_4-2-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldap-data-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-meta-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-meta-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-perl-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-perl-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sock-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sock-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sql-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-back-sql-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-client-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-client-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-contrib-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-contrib-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-debugsource-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-devel-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-devel-static-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-ppolicy-check-password-1.2-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openldap2-ppolicy-check-password-debuginfo-1.2-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldap-2_4-2-32bit-debuginfo-2.4.46-lp152.14.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"openldap2-devel-32bit-2.4.46-lp152.14.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libldap-2_4-2 / libldap-2_4-2-debuginfo / libldap-data / openldap2 / etc");
}
