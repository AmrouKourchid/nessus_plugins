#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2064.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128519);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/29");

  script_cve_id("CVE-2019-7164", "CVE-2019-7548");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"openSUSE Security Update : python-SQLAlchemy (openSUSE-2019-2064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for python-SQLAlchemy fixes the following issues :

Security issues fixed :

  - CVE-2019-7164: Fixed SQL Injection via the order_by
    parameter (bsc#1124593).

  - CVE-2019-7548: Fixed SQL Injection via the group_by
    parameter (bsc#1124593).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124593");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-SQLAlchemy packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-SQLAlchemy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-SQLAlchemy-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-SQLAlchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-SQLAlchemy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-SQLAlchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-SQLAlchemy-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"python-SQLAlchemy-debuginfo-1.2.14-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-SQLAlchemy-debugsource-1.2.14-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-SQLAlchemy-1.2.14-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-SQLAlchemy-debuginfo-1.2.14-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-SQLAlchemy-1.2.14-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-SQLAlchemy-debuginfo-1.2.14-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-SQLAlchemy-debuginfo / python-SQLAlchemy-debugsource / etc");
}
