#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-277.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146510);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2020-14352");

  script_name(english:"openSUSE Security Update : librepo (openSUSE-2021-277)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for librepo fixes the following issues :

  - Upgrade to 1.12.1

  + Validate path read from repomd.xml (bsc#1175475,
    CVE-2020-14352)

  - Changes from 1.12.0

  + Prefer mirrorlist/metalink over baseurl (rh#1775184)

  + Decode package URL when using for local filename
    (rh#1817130)

  + Fix memory leak in lr_download_metadata() and
    lr_yum_download_remote()

  + Download sources work when at least one of specified is
    working (rh#1775184)

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175475");
  script_set_attribute(attribute:"solution", value:
"Update the affected librepo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librepo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librepo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librepo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librepo0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librepo0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-librepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-librepo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE15.2", reference:"librepo-debuginfo-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librepo-debugsource-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librepo-devel-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librepo0-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librepo0-debuginfo-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-librepo-1.12.1-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-librepo-debuginfo-1.12.1-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librepo-debuginfo / librepo-debugsource / librepo-devel / librepo0 / etc");
}
