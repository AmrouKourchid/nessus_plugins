#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-802.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111564);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id("CVE-2017-14604");

  script_name(english:"openSUSE Security Update : nautilus (openSUSE-2018-802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for nautilus fixes the following issues :

Security issue fixed :

  - CVE-2017-14604: Add a metadata::trusted metadata to the
    file once the user acknowledges the file as trusted, and
    also remove the 'trusted' content in the desktop file
    (bsc#1060031).

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060031");
  script_set_attribute(attribute:"solution", value:
"Update the affected nautilus packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-shell-search-provider-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnautilus-extension1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnautilus-extension1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnautilus-extension1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnautilus-extension1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Nautilus-3_0");
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

if ( rpm_check(release:"SUSE42.3", reference:"gnome-shell-search-provider-nautilus-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libnautilus-extension1-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libnautilus-extension1-debuginfo-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-debuginfo-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-debugsource-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-devel-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nautilus-lang-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"typelib-1_0-Nautilus-3_0-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libnautilus-extension1-32bit-3.20.3-8.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libnautilus-extension1-debuginfo-32bit-3.20.3-8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-shell-search-provider-nautilus / libnautilus-extension1 / etc");
}
