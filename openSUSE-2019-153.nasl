#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-153.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122089);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id("CVE-2018-11803");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2019-153)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for subversion fixes the following issues :

Security issue fixed :

  - CVE-2018-11803: Fixed a vulnerability that allowed
    malicious SVN clients to trigger a crash in mod_dav_svn
    by omitting the root path from a recursive directory
    listing request (bsc#1122842)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122842");
  script_set_attribute(attribute:"solution", value:
"Update the affected subversion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_gnome_keyring-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsvn_auth_kwallet-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-ctypes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:subversion-tools-debuginfo");
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

if ( rpm_check(release:"SUSE15.0", reference:"libsvn_auth_gnome_keyring-1-0-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsvn_auth_kwallet-1-0-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-bash-completion-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-debugsource-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-devel-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-perl-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-perl-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-python-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-python-ctypes-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-python-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-ruby-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-ruby-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-server-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-server-debuginfo-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-tools-1.10.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"subversion-tools-debuginfo-1.10.0-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsvn_auth_gnome_keyring-1-0 / etc");
}
