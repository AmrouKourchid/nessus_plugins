#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-642.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(75114);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"openSUSE Security Update : mariadb / mysql-community-server (openSUSE-SU-2013:1335-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This version upgrade of mariadb fixed the following issues :

  - get rid of info which is not info (bnc#747811)

  - minor polishing of spec/installation

  - avoiding file conflicts with mytop

  - better fix for hardcoded libdir issue

  - making mysqldump work with MySQL 5.0 (bnc#768832)

  - fixed log rights (bnc#789263 and bnc#803040)

  - binlog disabled in default configuration (bnc#791863)

  - fixed dependencies for client package (bnc#780019)

Additionally, it includes multiple security fixes.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=747811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=768832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=780019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=789263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=791863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=803040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=830086");
  script_set_attribute(attribute:"see_also", value:"https://lists.opensuse.org/opensuse-updates/2013-08/msg00024.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb / mysql-community-server packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmariadbclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql55client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debug-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debug-version-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debug-version-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libmariadbclient18-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmariadbclient18-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmariadbclient_r18-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient-devel-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient18-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient18-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqlclient_r18-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld-devel-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld18-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libmysqld18-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-bench-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-bench-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-client-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-client-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-debug-version-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-debug-version-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-debugsource-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-errormessages-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-test-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-test-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-tools-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mariadb-tools-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-bench-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-bench-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-client-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-client-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debug-version-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debug-version-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-debugsource-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-errormessages-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-test-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-test-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-tools-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mysql-community-server-tools-debuginfo-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmariadbclient18-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmariadbclient18-debuginfo-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmariadbclient_r18-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.32-1.8.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysql55client18-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysql55client18-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysql55client_r18-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqlclient-devel-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqlclient18-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqlclient18-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqlclient_r18-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqld-devel-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqld18-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmysqld18-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-bench-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-bench-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-client-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-client-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-debug-version-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-debug-version-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-debugsource-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-errormessages-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-test-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-test-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-tools-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mariadb-tools-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-bench-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-bench-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-client-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-client-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-debug-version-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-debug-version-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-debugsource-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-errormessages-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-test-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-test-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-tools-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mysql-community-server-tools-debuginfo-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysql55client18-32bit-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysql55client18-debuginfo-32bit-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysql55client_r18-32bit-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysqlclient18-32bit-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-5.5.32-1.4.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-5.5.32-1.4.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmariadbclient18-32bit / libmariadbclient18 / etc");
}
