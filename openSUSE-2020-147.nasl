#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-147.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(133346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/28");

  script_cve_id(
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659"
  );

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2020-147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for java-1_8_0-openjdk fixes the following issues :

Update java-1_8_0-openjdk to version jdk8u242 (icedtea 3.15.0)
(January 2020 CPU, bsc#1160968) :

  - CVE-2020-2583: Unlink Set of LinkedHashSets

  - CVE-2020-2590: Improve Kerberos interop capabilities

  - CVE-2020-2593: Normalize normalization for all

  - CVE-2020-2601: Better Ticket Granting Services

  - CVE-2020-2604: Better serial filter handling

  - CVE-2020-2659: Enhance datagram socket support

  - CVE-2020-2654: Improve Object Identifier Processing

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160968");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1_8_0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-accessibility-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-demo-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-devel-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-headless-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-javadoc-1.8.0.242-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-1_8_0-openjdk-src-1.8.0.242-lp151.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
