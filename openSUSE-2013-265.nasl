#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-265.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74948);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-SU-2013:0560-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"clamav was updated to version 0.97.7 (bnc#809945) and contains several
hardening fixes which might be security issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=809945");
  script_set_attribute(attribute:"see_also", value:"https://lists.opensuse.org/opensuse-updates/2013-03/msg00116.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected clamav packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"clamav-0.97.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"clamav-db-0.97.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"clamav-debuginfo-0.97.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"clamav-debugsource-0.97.7-11.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"clamav-0.97.7-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"clamav-db-0.97.7-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"clamav-debuginfo-0.97.7-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"clamav-debugsource-0.97.7-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"clamav-0.97.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"clamav-debuginfo-0.97.7-5.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"clamav-debugsource-0.97.7-5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
