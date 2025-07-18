#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2021.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(143333);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/07");

  script_cve_id(
    "CVE-2019-8075",
    "CVE-2020-16012",
    "CVE-2020-16014",
    "CVE-2020-16015",
    "CVE-2020-16018",
    "CVE-2020-16019",
    "CVE-2020-16020",
    "CVE-2020-16021",
    "CVE-2020-16022",
    "CVE-2020-16023",
    "CVE-2020-16024",
    "CVE-2020-16025",
    "CVE-2020-16026",
    "CVE-2020-16027",
    "CVE-2020-16028",
    "CVE-2020-16029",
    "CVE-2020-16030",
    "CVE-2020-16031",
    "CVE-2020-16032",
    "CVE-2020-16033",
    "CVE-2020-16034",
    "CVE-2020-16035",
    "CVE-2020-16036"
  );

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2020-2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

  - Update to 87.0.4280.66 (boo#1178923)

  - Wayland support by default

  - CVE-2020-16018: Use after free in payments. 

  - CVE-2020-16019: Inappropriate implementation in
    filesystem. 

  - CVE-2020-16020: Inappropriate implementation in
    cryptohome. 

  - CVE-2020-16021: Race in ImageBurner. 

  - CVE-2020-16022: Insufficient policy enforcement in
    networking. 

  - CVE-2020-16015: Insufficient data validation in WASM. R

  - CVE-2020-16014: Use after free in PPAPI. 

  - CVE-2020-16023: Use after free in WebCodecs. 

  - CVE-2020-16024: Heap buffer overflow in UI.

  - CVE-2020-16025: Heap buffer overflow in clipboard. 

  - CVE-2020-16026: Use after free in WebRTC. 

  - CVE-2020-16027: Insufficient policy enforcement in
    developer tools. R

  - CVE-2020-16028: Heap buffer overflow in WebRTC. 

  - CVE-2020-16029: Inappropriate implementation in PDFium. 

  - CVE-2020-16030: Insufficient data validation in Blink. 

  - CVE-2019-8075: Insufficient data validation in Flash. 

  - CVE-2020-16031: Incorrect security UI in tab preview. 

  - CVE-2020-16032: Incorrect security UI in sharing.

  - CVE-2020-16033: Incorrect security UI in WebUSB. 

  - CVE-2020-16034: Inappropriate implementation in WebRTC. 

  - CVE-2020-16035: Insufficient data validation in
    cros-disks.

  - CVE-2020-16012: Side-channel information leakage in
    graphics. 

  - CVE-2020-16036: Inappropriate implementation in cookies.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178923");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16035");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-16025");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-87.0.4280.66-lp152.2.51.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromedriver-debuginfo-87.0.4280.66-lp152.2.51.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-87.0.4280.66-lp152.2.51.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"chromium-debuginfo-87.0.4280.66-lp152.2.51.1", allowmaj:TRUE) ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
