#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1206.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(139649);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/26");

  script_cve_id(
    "CVE-2020-6542",
    "CVE-2020-6543",
    "CVE-2020-6544",
    "CVE-2020-6545",
    "CVE-2020-6546",
    "CVE-2020-6547",
    "CVE-2020-6548",
    "CVE-2020-6549",
    "CVE-2020-6550",
    "CVE-2020-6551",
    "CVE-2020-6552",
    "CVE-2020-6553",
    "CVE-2020-6554",
    "CVE-2020-6555"
  );

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-1206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

  - Chromium updated to 84.0.4147.125 (boo#1175085)

  - CVE-2020-6542: Use after free in ANGLE

  - CVE-2020-6543: Use after free in task scheduling

  - CVE-2020-6544: Use after free in media

  - CVE-2020-6545: Use after free in audio

  - CVE-2020-6546: Inappropriate implementation in installer

  - CVE-2020-6547: Incorrect security UI in media

  - CVE-2020-6548: Heap buffer overflow in Skia

  - CVE-2020-6549: Use after free in media

  - CVE-2020-6550: Use after free in IndexedDB

  - CVE-2020-6551: Use after free in WebXR

  - CVE-2020-6552: Use after free in Blink

  - CVE-2020-6553: Use after free in offline mode

  - CVE-2020-6554: Use after free in extensions

  - CVE-2020-6555: Out of bounds read in WebGL

  - Various fixes from internal audits, fuzzing and other
    initiatives

  - Disable wayland everywhere as it breaks headless and
    middle mouse copy everywhere: boo#1174497 boo#1175044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175085");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6553");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-84.0.4147.125-lp151.2.115.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-84.0.4147.125-lp151.2.115.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-84.0.4147.125-lp151.2.115.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-84.0.4147.125-lp151.2.115.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-84.0.4147.125-lp151.2.115.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-84.0.4147.125-lp152.2.12.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-84.0.4147.125-lp152.2.12.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-84.0.4147.125-lp152.2.12.2", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-84.0.4147.125-lp152.2.12.2", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debugsource-84.0.4147.125-lp152.2.12.2", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
