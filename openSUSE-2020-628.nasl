#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-628.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(136455);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/13");

  script_cve_id("CVE-2020-12050");

  script_name(english:"openSUSE Security Update : sqliteodbc (openSUSE-2020-628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for sqliteodbc fixes the following issues :

Security issue fixed :

  - CVE-2020-12050: Fixed a privilege escalation
    vulnerability (boo#1171041).

Non-security issues fixed :

  - Update to version 0.9996

  - update to SQLite 3.22.0

  - fixes in handling DDL in SQLExecDirect() et.al., thanks
    Andre Mikulec for testing

  - cleanup utf8/unicode conversion functions");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171041");
  script_set_attribute(attribute:"solution", value:
"Update the affected sqliteodbc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sqliteodbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sqliteodbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sqliteodbc-debugsource");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"sqliteodbc-0.9996-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sqliteodbc-debuginfo-0.9996-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sqliteodbc-debugsource-0.9996-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sqliteodbc / sqliteodbc-debuginfo / sqliteodbc-debugsource");
}
