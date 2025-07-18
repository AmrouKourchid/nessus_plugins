#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1202.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104238);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2017-12166");
  script_xref(name:"IAVA", value:"2017-A-0285-S");

  script_name(english:"openSUSE Security Update : openvpn (openSUSE-2017-1202)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openvpn fixes the following issues :

  - CVE-2017-12166: Lack of bound check in read_key in old
    legacy key handling before using values could be used
    for a remote buffer overflow (bsc#1060877).

This update was imported from the SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060877");
  script_set_attribute(attribute:"solution", value:
"Update the affected openvpn packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 Tenable Network Security, Inc.");

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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"openvpn-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debuginfo-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debugsource-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-devel-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-debuginfo-2.3.8-8.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-auth-pam-plugin-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-debuginfo-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-debugsource-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-devel-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-down-root-plugin-2.3.8-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openvpn-down-root-plugin-debuginfo-2.3.8-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn / openvpn-auth-pam-plugin / etc");
}
