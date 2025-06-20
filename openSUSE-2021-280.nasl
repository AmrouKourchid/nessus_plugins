#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-280.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146508);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/11");

  script_cve_id("CVE-2020-17525");
  script_xref(name:"IAVA", value:"2021-A-0094-S");

  script_name(english:"openSUSE Security Update : subversion (openSUSE-2021-280)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for subversion fixes the following issues :

  - CVE-2020-17525: A null-pointer-dereference has been
    found in mod_authz_svn that results in a remote
    unauthenticated Denial-of-Service in some server
    configurations (bsc#1181687).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181687");
  script_set_attribute(attribute:"solution", value:
"Update the affected subversion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17525");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE15.2", reference:"libsvn_auth_gnome_keyring-1-0-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvn_auth_gnome_keyring-1-0-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvn_auth_kwallet-1-0-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libsvn_auth_kwallet-1-0-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-bash-completion-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-debugsource-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-devel-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-perl-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-perl-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-python-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-python-ctypes-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-python-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-ruby-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-ruby-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-server-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-server-debuginfo-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-tools-1.10.6-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"subversion-tools-debuginfo-1.10.6-lp152.2.9.1") ) flag++;

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
