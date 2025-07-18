#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-490.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110064);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/03");

  script_cve_id(
    "CVE-2015-1239",
    "CVE-2017-171479",
    "CVE-2017-17479",
    "CVE-2017-17480"
  );

  script_name(english:"openSUSE Security Update : openjpeg2 (openSUSE-2018-490)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openjpeg2 fixes the following security issues :

  - CVE-2015-1239: A double free vulnerability in the
    j2k_read_ppm_v3 function allowed remote attackers to
    cause a denial of service (crash) (bsc#1066713)

  - CVE-2017-17479: A stack-based buffer overflow in the
    pgxtoimage function in jpwl/convert.c could crash the
    converter. (bsc#1072125)

  - CVE-2017-17480: A stack-based buffer overflow in the
    pgxtovolume function in jp3d/convert.c could crash the
    converter. (bsc#1072124)

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072125");
  script_set_attribute(attribute:"solution", value:
"Update the affected openjpeg2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenjp2-7-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openjpeg2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
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

if ( rpm_check(release:"SUSE42.3", reference:"libopenjp2-7-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopenjp2-7-debuginfo-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-debuginfo-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-debugsource-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openjpeg2-devel-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenjp2-7-32bit-2.1.0-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libopenjp2-7-debuginfo-32bit-2.1.0-22.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenjp2-7 / libopenjp2-7-32bit / libopenjp2-7-debuginfo / etc");
}
