#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2317.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(129998);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2019-16709");

  script_name(english:"openSUSE Security Update : GraphicsMagick (openSUSE-2019-2317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for GraphicsMagick fixes the following issues :

  - CVE-2019-16709: Fixed a memory leak in coders/dps.c
    (boo#1151782).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151782");
  script_set_attribute(attribute:"solution", value:
"Update the affected GraphicsMagick packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16709");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:GraphicsMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-Q16-12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick-Q16-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagick3-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libGraphicsMagickWand-Q16-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-GraphicsMagick-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"GraphicsMagick-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"GraphicsMagick-debuginfo-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"GraphicsMagick-debugsource-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"GraphicsMagick-devel-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick++-Q16-12-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick++-Q16-12-debuginfo-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick++-devel-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick-Q16-3-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick-Q16-3-debuginfo-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagick3-config-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagickWand-Q16-2-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libGraphicsMagickWand-Q16-2-debuginfo-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-GraphicsMagick-1.3.29-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-GraphicsMagick-debuginfo-1.3.29-lp151.4.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "GraphicsMagick / GraphicsMagick-debuginfo / etc");
}
