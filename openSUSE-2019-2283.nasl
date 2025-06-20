#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2283.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(129711);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2019-9893");

  script_name(english:"openSUSE Security Update : libseccomp (openSUSE-2019-2283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libseccomp fixes the following issues :

Security issues fixed :

  - CVE-2019-9893: An incorrect generation of syscall
    filters in libseccomp was fixed (bsc#1128828)

libseccomp was updated to new upstream release 2.4.1 :

  - Fix a BPF generation bug where the optimizer mistakenly
    identified duplicate BPF code blocks.

libseccomp was updated to 2.4.0 (bsc#1128828 CVE-2019-9893) :

  - Update the syscall table for Linux v5.0-rc5

  - Added support for the SCMP_ACT_KILL_PROCESS action

  - Added support for the SCMP_ACT_LOG action and
    SCMP_FLTATR_CTL_LOG attribute

  - Added explicit 32-bit (SCMP_AX_32(...)) and 64-bit
    (SCMP_AX_64(...)) argument comparison macros to help
    protect against unexpected sign extension

  - Added support for the parisc and parisc64 architectures

  - Added the ability to query and set the libseccomp API
    level via seccomp_api_get(3) and seccomp_api_set(3)

  - Return -EDOM on an endian mismatch when adding an
    architecture to a filter

  - Renumber the pseudo syscall number for subpage_prot() so
    it no longer conflicts with spu_run()

  - Fix PFC generation when a syscall is prioritized, but no
    rule exists

  - Numerous fixes to the seccomp-bpf filter generation code

  - Switch our internal hashing function to jhash/Lookup3 to
    MurmurHash3

  - Numerous tests added to the included test suite,
    coverage now at ~92%

  - Update our Travis CI configuration to use Ubuntu 16.04

  - Numerous documentation fixes and updates

libseccomp was updated to release 2.3.3 :

  - Updated the syscall table for Linux v4.15-rc7

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142614");
  script_set_attribute(attribute:"solution", value:
"Update the affected libseccomp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9893");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libseccomp2-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"libseccomp-debugsource-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libseccomp-devel-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libseccomp-tools-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libseccomp-tools-debuginfo-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libseccomp2-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libseccomp2-debuginfo-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libseccomp2-32bit-2.4.1-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libseccomp2-32bit-debuginfo-2.4.1-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libseccomp-debugsource / libseccomp-devel / libseccomp-tools / etc");
}
