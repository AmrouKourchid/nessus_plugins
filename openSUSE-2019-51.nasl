#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-51.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121157);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/26");

  script_cve_id("CVE-2018-10852");

  script_name(english:"openSUSE Security Update : sssd (openSUSE-2019-51)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for sssd provides the following fixes :

This security issue was fixed :

  - CVE-2018-10852: Set stricter permissions on
    /var/lib/sss/pipes/sudo to prevent the disclosure of
    sudo rules for arbitrary users (bsc#1098377)

These non-security issues were fixed :

  - Fix a segmentation fault in sss_cache command.
    (bsc#1072728)

  - Fix a failure in autofs initialisation sequence upon
    system boot. (bsc#1010700)

  - Fix race condition on boot between SSSD and autofs.
    (bsc#1010700)

  - Fix a bug where file descriptors were not closed
    (bsc#1080156)

  - Fix an issue where sssd logs were not rotated properly
    (bsc#1080156)

  - Remove whitespaces from netgroup entries (bsc#1087320)

  - Remove misleading log messages (bsc#1101877)

  - exit() the forked process if exec()-ing a child process
    fails (bsc#1110299)

  - Do not schedule the machine renewal task if adcli is not
    executable (bsc#1110299)

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1072728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1098377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110299");
  script_set_attribute(attribute:"solution", value:
"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10852");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools-debuginfo");
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

if ( rpm_check(release:"SUSE42.3", reference:"libipa_hbac-devel-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libipa_hbac0-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libipa_hbac0-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_idmap-devel-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_idmap0-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_idmap0-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_nss_idmap-devel-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_nss_idmap0-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_nss_idmap0-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_sudo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsss_sudo-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-ipa_hbac-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-ipa_hbac-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-sss_nss_idmap-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-sss_nss_idmap-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-sssd-config-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-sssd-config-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ad-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ad-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-debugsource-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ipa-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ipa-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-krb5-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-krb5-common-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-krb5-common-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-krb5-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ldap-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-ldap-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-proxy-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-proxy-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-tools-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"sssd-tools-debuginfo-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sssd-32bit-1.13.4-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.13.4-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac-devel / libipa_hbac0 / libipa_hbac0-debuginfo / etc");
}
