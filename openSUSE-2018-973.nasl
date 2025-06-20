#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-973.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117352);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2017-15130");

  script_name(english:"openSUSE Security Update : dovecot22 (openSUSE-2018-973)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for dovecot22 fixes the following issues :

Security issue fixed :

  - CVE-2017-15130: Fixed a potential denial of service via
    TLS SNI config lookups, which would slow the process
    down and could have led to exhaustive memory allocation
    and/or process restarts (bsc#1082828)

This update was imported from the SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082828");
  script_set_attribute(attribute:"solution", value:
"Update the affected dovecot22 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15130");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-backend-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-lucene-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-solr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dovecot22-fts-squat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-mysql-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-mysql-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-pgsql-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-pgsql-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-sqlite-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-backend-sqlite-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-debugsource-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-devel-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-lucene-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-lucene-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-solr-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-solr-debuginfo-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-squat-2.2.31-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"dovecot22-fts-squat-debuginfo-2.2.31-2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot22 / dovecot22-backend-mysql / etc");
}
