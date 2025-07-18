#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2033.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128453);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2019-15540");

  script_name(english:"openSUSE Security Update : libmirage (openSUSE-2019-2033)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libmirage fixes the following issues :

CVE-2019-15540: The CSO filter in libMirage in CDemu did not validate
the part size, triggering a heap-based buffer overflow that could lead
to root access by a local user. [boo#1148087]

  - Update to new upstream release 3.2.2

  - ISO parser: fixed ISO9660/UDF pattern search for sector
    sizes 2332 and 2336.

  - ISO parser: added support for Nintendo GameCube and Wii
    ISO images.

  - Extended medium type guess to distinguish between DVD
    and BluRay images based on length.

  - Removed fabrication of disc structures from the library
    (moved to CDEmu daemon).

  - MDS parser: cleanup of disc structure parsing, fixed the
    incorrectly set structure sizes.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1148087");
  script_set_attribute(attribute:"solution", value:
"Update the affected libmirage packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-3_2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmirage11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-libmirage-3_2");
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

if ( rpm_check(release:"SUSE15.1", reference:"libmirage-3_2-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-3_2-debuginfo-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-data-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-debuginfo-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-debugsource-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-devel-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage-lang-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage11-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmirage11-debuginfo-3.2.2-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-libmirage-3_2-3.2.2-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmirage-3_2 / libmirage-3_2-debuginfo / libmirage-data / etc");
}
