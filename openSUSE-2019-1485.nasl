#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1485.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125670);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2015-6806");

  script_name(english:"openSUSE Security Update : screen (openSUSE-2019-1485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for screen fixes the following issues :

Security issue fixed :

  - CVE-2015-6806: Fixed a stack overflow due to deep
    recursion (bsc#944458).

Non-security issue fixed :

  - Fixed segmentation faults related to altscreen and
    resizing screen (bsc#1130831).

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1130831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=944458");
  script_set_attribute(attribute:"solution", value:
"Update the affected screen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6806");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:screen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:screen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:screen-debugsource");
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

if ( rpm_check(release:"SUSE42.3", reference:"screen-4.0.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"screen-debuginfo-4.0.4-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"screen-debugsource-4.0.4-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "screen / screen-debuginfo / screen-debugsource");
}
