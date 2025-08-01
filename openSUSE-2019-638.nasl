#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-638.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123276);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/11");

  script_cve_id(
    "CVE-2018-10887",
    "CVE-2018-10888",
    "CVE-2018-11235",
    "CVE-2018-15501"
  );

  script_name(english:"openSUSE Security Update : libgit2 (openSUSE-2019-638)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libgit2 to version 0.26.5 fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-10887: Fixed an integer overflow which in turn
    leads to an out of bound read, allowing to read the base
    object, which could be exploited by an attacker to cause
    denial of service (DoS) (bsc#1100613).

  - CVE-2018-10888: Fixed an out-of-bound read while reading
    a binary delta file, which could be exploited by an
    attacker t ocause a denial of service (DoS)
    (bsc#1100612).

  - CVE-2018-11235: Fixed a remote code execution, which
    could occur with a crafted .gitmodules file
    (bsc#1095219)

  - CVE-2018-15501: Prevent out-of-bounds reads when
    processing smart-protocol 'ng' packets (bsc#1104641)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104641");
  script_set_attribute(attribute:"solution", value:
"Update the affected libgit2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11235");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-26-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-26-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-devel");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libgit2-26-0.26.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgit2-26-debuginfo-0.26.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgit2-debugsource-0.26.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgit2-devel-0.26.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgit2-26-32bit-0.26.6-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgit2-26-32bit-debuginfo-0.26.6-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgit2-26 / libgit2-26-32bit / libgit2-26-32bit-debuginfo / etc");
}
