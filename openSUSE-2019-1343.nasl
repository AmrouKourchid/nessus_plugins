#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1343.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124708);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2018-1152", "CVE-2018-11813", "CVE-2018-14498");
  script_xref(name:"TRA", value:"TRA-2018-17");

  script_name(english:"openSUSE Security Update : libjpeg-turbo (openSUSE-2019-1343)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libjpeg-turbo fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-14498: Fixed a heap-based buffer over read in
    get_8bit_row function which could allow to an attacker
    to cause denial of service (bsc#1128712).

  - CVE-2018-11813: Fixed the end-of-file mishandling in
    read_pixel in rdtarga.c, which allowed remote attackers
    to cause a denial-of-service via crafted JPG files due
    to a large loop (bsc#1096209)

  - CVE-2018-1152: Fixed a denial of service in
    start_input_bmp() rdbmp.c caused by a divide by zero
    when processing a crafted BMP image (bsc#1098155)

This update was imported from the SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128712");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-17");
  script_set_attribute(attribute:"solution", value:
"Update the affected libjpeg-turbo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg62-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjpeg8-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libturbojpeg0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libjpeg-turbo-1.5.3-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg-turbo-debuginfo-1.5.3-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg-turbo-debugsource-1.5.3-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg62-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg62-debuginfo-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg62-devel-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg62-turbo-1.5.3-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg62-turbo-debugsource-1.5.3-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg8-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg8-debuginfo-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libjpeg8-devel-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libturbojpeg0-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libturbojpeg0-debuginfo-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg62-32bit-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg62-debuginfo-32bit-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg62-devel-32bit-62.2.0-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg8-32bit-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg8-debuginfo-32bit-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libjpeg8-devel-32bit-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libturbojpeg0-32bit-8.1.2-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libturbojpeg0-debuginfo-32bit-8.1.2-45.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo / libjpeg-turbo-debuginfo / libjpeg-turbo-debugsource / etc");
}
