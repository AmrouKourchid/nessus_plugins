#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-485.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(148315);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/05");

  script_cve_id("CVE-2020-27225");

  script_name(english:"openSUSE Security Update : eclipse (openSUSE-2021-485)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for eclipse fixes the following issues :

  - CVE-2020-27225: Authenticate active help requests to the
    local help web server (bsc#1183728).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183728");
  script_set_attribute(attribute:"solution", value:
"Update the affected eclipse packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27225");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-contributor-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-contributor-tools-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-equinox-osgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-equinox-osgi-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-jdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-jdt-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-p2-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-p2-discovery-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-pde-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-platform-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-platform-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-platform-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-swt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-swt-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-swt-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-swt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:eclipse-tests-bootstrap");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"eclipse-bootstrap-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-bootstrap-debugsource-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-contributor-tools-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-contributor-tools-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-debugsource-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-equinox-osgi-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-equinox-osgi-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-jdt-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-jdt-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-p2-discovery-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-p2-discovery-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-pde-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-pde-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-platform-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-platform-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-platform-bootstrap-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-platform-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-swt-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-swt-bootstrap-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-swt-bootstrap-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-swt-debuginfo-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-tests-4.9.0-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"eclipse-tests-bootstrap-4.9.0-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eclipse-contributor-tools / eclipse-debuginfo / eclipse-debugsource / etc");
}
