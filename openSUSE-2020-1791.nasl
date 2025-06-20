#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1791.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142190);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id(
    "CVE-2020-12861",
    "CVE-2020-12862",
    "CVE-2020-12863",
    "CVE-2020-12864",
    "CVE-2020-12865",
    "CVE-2020-12866",
    "CVE-2020-12867"
  );

  script_name(english:"openSUSE Security Update : sane-backends (openSUSE-2020-1791)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for sane-backends fixes the following issues :

sane-backends was updated to 1.0.31 to further improve hardware
enablement for scanner devices (jsc#ECO-2418 jsc#SLE-15561
jsc#SLE-15560) and also fix various security issues :

  - CVE-2020-12861,CVE-2020-12865: Fixed an out of bounds
    write (bsc#1172524)

  - CVE-2020-12862,CVE-2020-12863,CVE-2020-12864,: Fixed an
    out of bounds read (bsc#1172524)

  - CVE-2020-12866,CVE-2020-12867: Fixed a NULL pointer
    dereference (bsc#1172524)

The upstream changelogs can be found here :

- https://gitlab.com/sane-project/backends/-/releases/1.0.28

- https://gitlab.com/sane-project/backends/-/releases/1.0.29

- https://gitlab.com/sane-project/backends/-/releases/1.0.30

- https://gitlab.com/sane-project/backends/-/releases/1.0.31

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172524");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/sane-project/backends/-/releases/1.0.28");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/sane-project/backends/-/releases/1.0.29");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/sane-project/backends/-/releases/1.0.30");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.com/sane-project/backends/-/releases/1.0.31");
  script_set_attribute(attribute:"solution", value:
"Update the affected sane-backends packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-autoconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sane-backends-devel-32bit");
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

if ( rpm_check(release:"SUSE15.1", reference:"sane-backends-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sane-backends-autoconfig-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sane-backends-debuginfo-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sane-backends-debugsource-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"sane-backends-devel-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"sane-backends-32bit-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"sane-backends-32bit-debuginfo-1.0.31-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"sane-backends-devel-32bit-1.0.31-lp151.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sane-backends / sane-backends-autoconfig / sane-backends-debuginfo / etc");
}
