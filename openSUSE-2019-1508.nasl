#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1508.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(125719);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2019-5436");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2019-1508)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for curl fixes the following issues :

Security issue fixed :

  - CVE-2019-5436: Fixed a heap buffer overflow exists in
    tftp_receive_packet that receives data from a TFTP
    server (bsc#1135170).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135170");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5436");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-mini-debuginfo");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"curl-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"curl-debuginfo-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"curl-debugsource-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"curl-mini-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"curl-mini-debuginfo-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"curl-mini-debugsource-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl-devel-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl-mini-devel-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl4-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl4-debuginfo-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl4-mini-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libcurl4-mini-debuginfo-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libcurl-devel-32bit-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libcurl4-32bit-7.60.0-lp151.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.60.0-lp151.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl-mini / curl-mini-debuginfo / curl-mini-debugsource / etc");
}
