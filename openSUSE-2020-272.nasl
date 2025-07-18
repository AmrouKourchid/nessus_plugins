#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-272.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(134195);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_cve_id(
    "CVE-2009-4112",
    "CVE-2018-20723",
    "CVE-2018-20724",
    "CVE-2018-20725",
    "CVE-2018-20726",
    "CVE-2019-16723",
    "CVE-2019-17357",
    "CVE-2019-17358",
    "CVE-2020-7106",
    "CVE-2020-7237"
  );

  script_name(english:"openSUSE Security Update : cacti / cacti-spine (openSUSE-2020-272)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for cacti, cacti-spine fixes the following issues :

cacti-spine was updated to version 1.2.9.

Security issues fixed :

  - CVE-2009-4112: Fixed a privilege escalation
    (bsc#1122535).

  - CVE-2018-20723: Fixed a cross-site scripting (XSS)
    vulnerability (bsc#1122245).

  - CVE-2018-20724: Fixed a cross-site scripting (XSS)
    vulnerability (bsc#1122244).

  - CVE-2018-20725: Fixed a privilege escalation that could
    occur under certain conditions (bsc#1122535).

  - CVE-2018-20726: Fixed a cross-site scripting (XSS)
    vulnerability (bsc#1122242).

  - CVE-2019-16723: Fixed an authentication bypass
    vulnerability.

  - CVE-2019-17357: Fixed a SQL injection vulnerability
    (bsc#1158990).

  - CVE-2019-17358: Fixed an unsafe deserialization in
    sanitize_unserialize_selected_items (bsc#1158992).

  - CVE-2020-7106: Fixed a potential cross-site scripting
    (XSS) vulnerability (bsc#1163749).

  - CVE-2020-7237: Fixed a remote code execution that
    affected privileged users via shell metacharacters in
    the Performance Boost Debug Log field (bsc#1161297).

Non-security issues fixed :

  - Fixed missing packages php-json, php-ctype, and php-gd
    in cacti.spec (boo#1101024).

  - Fixed Apache2.4 and Apache2.2 runtime configuration
    issue (boo#1101139).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163749");
  script_set_attribute(attribute:"see_also", value:"https://features.opensuse.org/326485");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti / cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7237");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine-debugsource");
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

if ( rpm_check(release:"SUSE15.1", reference:"cacti-1.2.9-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-1.2.9-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-debuginfo-1.2.9-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cacti-spine-debugsource-1.2.9-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cacti-spine / cacti-spine-debuginfo / cacti-spine-debugsource / etc");
}
