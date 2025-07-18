#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-455.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109752);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/08");

  script_cve_id("CVE-2016-1516", "CVE-2016-1517");

  script_name(english:"openSUSE Security Update : opencv (openSUSE-2018-455)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for opencv fixes the following issues :

  - CVE-2016-1517: Fixed a denial of service (segfault) via
    vectors involving corrupt chunks (boo#1033150)

  - CVE-2016-1516: Fixed a double free issue that allows
    attackers to execute arbitrary code (boo#1033152).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033152");
  script_set_attribute(attribute:"solution", value:
"Update the affected opencv packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv-qt56_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv-qt56_3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-qt5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-opencv-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-qt5-debuginfo");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libopencv-qt56_3-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv-qt56_3-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv3_1-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libopencv3_1-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-debugsource-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-devel-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-debugsource-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"opencv-qt5-devel-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-qt5-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-opencv-qt5-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-debuginfo-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-qt5-3.1.0-4.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-opencv-qt5-debuginfo-3.1.0-4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopencv-qt56_3 / libopencv-qt56_3-debuginfo / opencv-qt5 / etc");
}
