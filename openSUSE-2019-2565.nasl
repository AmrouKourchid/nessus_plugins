#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2565.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(131301);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/09");

  script_cve_id(
    "CVE-2019-2894",
    "CVE-2019-2933",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2958",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2977",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999"
  );

  script_name(english:"openSUSE Security Update : java-11-openjdk (openSUSE-2019-2565)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for java-11-openjdk to version jdk-11.0.5-10 fixes the
following issues :

Security issues fixed (October 2019 CPU bsc#1154212):&#9; 

  - CVE-2019-2933: Windows file handling redux

  - CVE-2019-2945: Better socket support

  - CVE-2019-2949: Better Kerberos ccache handling

  - CVE-2019-2958: Build Better Processes

  - CVE-2019-2964: Better support for patterns

  - CVE-2019-2962: Better Glyph Images

  - CVE-2019-2973: Better pattern compilation

  - CVE-2019-2975: Unexpected exception in jjs

  - CVE-2019-2978: Improved handling of jar files

  - CVE-2019-2977: Improve String index handling

  - CVE-2019-2981: Better Path supports

  - CVE-2019-2983: Better serial attributes

  - CVE-2019-2987: Better rendering of native glyphs

  - CVE-2019-2988: Better Graphics2D drawing

  - CVE-2019-2989: Improve TLS connection support

  - CVE-2019-2992: Enhance font glyph mapping

  - CVE-2019-2999: Commentary on Javadoc comments

  - CVE-2019-2894: Enhance ECDSA operations (bsc#1152856).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154212");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2977");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-11-openjdk-src");
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

if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-accessibility-debuginfo-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debuginfo-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-debugsource-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-demo-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-devel-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-headless-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-javadoc-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-jmods-11.0.5.0-lp151.3.9.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"java-11-openjdk-src-11.0.5.0-lp151.3.9.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-accessibility / etc");
}
