#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-372.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(147158);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2021-22883", "CVE-2021-22884", "CVE-2021-23840");
  script_xref(name:"IAVB", value:"2021-B-0012-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : nodejs10 (openSUSE-2021-372)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs10 fixes the following issues :

New upstream LTS version 10.24.0 :

  - CVE-2021-22883: HTTP2 'unknownProtocol' cause Denial of
    Service by resource exhaustion (bsc#1182619)

  - CVE-2021-22884: DNS rebinding in --inspect (bsc#1182620)

  - CVE-2021-23840: OpenSSL - Integer overflow in
    CipherUpdate (bsc#1182333)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182620");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22884");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"nodejs10-10.24.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nodejs10-debuginfo-10.24.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nodejs10-debugsource-10.24.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nodejs10-devel-10.24.0-lp152.2.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"npm10-10.24.0-lp152.2.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs10 / nodejs10-debuginfo / nodejs10-debugsource / etc");
}
