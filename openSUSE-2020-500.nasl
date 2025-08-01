#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-500.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(135448);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/19");

  script_cve_id(
    "CVE-2018-13441",
    "CVE-2018-13457",
    "CVE-2018-13458",
    "CVE-2018-18245",
    "CVE-2019-3698"
  );

  script_name(english:"openSUSE Security Update : nagios (openSUSE-2020-500)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nagios to version 4.4.5 fixes the following issues :

  - CVE-2019-3698: Symbolic link following vulnerability in
    the cronjob allows local attackers to cause cause DoS or
    potentially escalate privileges. (boo#1156309)

  - CVE-2018-18245: Fixed XSS vulnerability in Alert Summary
    report (boo#1119832)

  - CVE-2018-13441, CVE-2018-13458, CVE-2018-13457: Fixed a
    few denial of service vulnerabilities caused by NULL
    pointer dereference (boo#1101293, boo#1101289,
    boo#1101290).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1119832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156309");
  script_set_attribute(attribute:"solution", value:
"Update the affected nagios packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3698");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-theme-exfoliation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-dch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nagios-www-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"nagios-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-contrib-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-debuginfo-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-debugsource-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-devel-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-theme-exfoliation-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-www-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-www-dch-4.4.5-lp151.5.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nagios-www-debuginfo-4.4.5-lp151.5.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios / nagios-contrib / nagios-debuginfo / nagios-debugsource / etc");
}
