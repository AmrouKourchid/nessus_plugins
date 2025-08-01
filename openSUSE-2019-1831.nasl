#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1831.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127739);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id(
    "CVE-2016-1238",
    "CVE-2017-15705",
    "CVE-2018-11780",
    "CVE-2018-11781"
  );

  script_name(english:"openSUSE Security Update : spamassassin (openSUSE-2019-1831)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for spamassassin to version 3.4.2 fixes the following
issues :

Security issues fixed :

  - CVE-2018-11781: Fixed an issue where a local user could
    inject code in the meta rule syntax (bsc#1108748).

  - CVE-2018-11780: Fixed a potential remote code execution
    vulnerability in the PDFInfo plugin (bsc#1108750).

  - CVE-2017-15705: Fixed a denial of service through
    unclosed tags in crafted emails (bsc#1108745).

  - CVE-2016-1238: Fixed an issue where perl would load
    modules from the current directory (bsc#1108749).

Non-security issues fixed :

  - Use systemd timers instead of cron (bsc#1115411)

  - Fixed incompatibility with Net::DNS >= 1.01
    (bsc#1107765)

  - Fixed warning about deprecated regex during sa-update
    (bsc#1069831)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115411");
  script_set_attribute(attribute:"solution", value:
"Update the affected spamassassin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Mail-SpamAssassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-Mail-SpamAssassin-Plugin-iXhash2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spamassassin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:spamassassin-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"perl-Mail-SpamAssassin-3.4.2-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"perl-Mail-SpamAssassin-Plugin-iXhash2-2.05-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"spamassassin-3.4.2-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"spamassassin-debuginfo-3.4.2-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"spamassassin-debugsource-3.4.2-lp150.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Mail-SpamAssassin / perl-Mail-SpamAssassin-Plugin-iXhash2 / etc");
}
