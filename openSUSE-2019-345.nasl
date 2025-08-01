#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-345.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122942);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/13");

  script_cve_id(
    "CVE-2018-10360",
    "CVE-2019-8905",
    "CVE-2019-8906",
    "CVE-2019-8907"
  );

  script_name(english:"openSUSE Security Update : file (openSUSE-2019-345)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for file fixes the following issues :

The following security vulnerabilities were addressed :

  - CVE-2018-10360: Fixed an out-of-bounds read in the
    function do_core_note in readelf.c, which allowed remote
    attackers to cause a denial of service (application
    crash) via a crafted ELF file (bsc#1096974)

  - CVE-2019-8905: Fixed a stack-based buffer over-read in
    do_core_note in readelf.c (bsc#1126118)

  - CVE-2019-8906: Fixed an out-of-bounds read in
    do_core_note in readelf. c (bsc#1126119)

  - CVE-2019-8907: Fixed a stack corruption in do_core_note
    in readelf.c (bsc#1126117)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126119");
  script_set_attribute(attribute:"solution", value:
"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8907");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-magic");
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

if ( rpm_check(release:"SUSE15.0", reference:"file-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"file-debuginfo-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"file-debugsource-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"file-devel-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"file-magic-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmagic1-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libmagic1-debuginfo-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-magic-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-magic-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"file-devel-32bit-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmagic1-32bit-5.32-lp150.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libmagic1-32bit-debuginfo-5.32-lp150.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-debugsource / file-devel-32bit / etc");
}
