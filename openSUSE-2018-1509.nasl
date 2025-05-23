#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1509.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119542);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/16");

  script_cve_id("CVE-2018-19211");

  script_name(english:"openSUSE Security Update : ncurses (openSUSE-2018-1509)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for ncurses fixes the following issue :

Security issue fixed :

  - CVE-2018-19211: Fixed denial of service issue that was
    triggered by a NULL pointer dereference at function
    _nc_parse_entry (bsc#1115929).

This update was imported from the SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115929");
  script_set_attribute(attribute:"solution", value:
"Update the affected ncurses packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19211");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libncurses6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ncurses-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:terminfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:terminfo-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libncurses5-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libncurses5-debuginfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libncurses6-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libncurses6-debuginfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ncurses-debugsource-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ncurses-devel-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ncurses-devel-debuginfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ncurses-utils-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ncurses-utils-debuginfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tack-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tack-debuginfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"terminfo-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"terminfo-base-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libncurses5-32bit-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libncurses5-debuginfo-32bit-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libncurses6-32bit-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libncurses6-debuginfo-32bit-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ncurses-devel-32bit-5.9-66.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"ncurses-devel-debuginfo-32bit-5.9-66.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libncurses5-32bit / libncurses5 / libncurses5-debuginfo-32bit / etc");
}
