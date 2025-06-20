#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2692.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(132087);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/04");

  script_cve_id(
    "CVE-2019-13725",
    "CVE-2019-13726",
    "CVE-2019-13727",
    "CVE-2019-13728",
    "CVE-2019-13729",
    "CVE-2019-13730",
    "CVE-2019-13732",
    "CVE-2019-13734",
    "CVE-2019-13735",
    "CVE-2019-13736",
    "CVE-2019-13737",
    "CVE-2019-13738",
    "CVE-2019-13739",
    "CVE-2019-13740",
    "CVE-2019-13741",
    "CVE-2019-13742",
    "CVE-2019-13743",
    "CVE-2019-13744",
    "CVE-2019-13745",
    "CVE-2019-13746",
    "CVE-2019-13747",
    "CVE-2019-13748",
    "CVE-2019-13749",
    "CVE-2019-13750",
    "CVE-2019-13751",
    "CVE-2019-13752",
    "CVE-2019-13753",
    "CVE-2019-13754",
    "CVE-2019-13755",
    "CVE-2019-13756",
    "CVE-2019-13757",
    "CVE-2019-13758",
    "CVE-2019-13759",
    "CVE-2019-13761",
    "CVE-2019-13762",
    "CVE-2019-13763",
    "CVE-2019-13764"
  );

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2019-2692)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for chromium fixes the following issues :

Chromium was updated to 79.0.3945.79 (boo#1158982)&#9; 

  - CVE-2019-13725: Fixed a use after free in Bluetooth

  - CVE-2019-13726: Fixed a heap buffer overflow in password
    manager

  - CVE-2019-13727: Fixed an insufficient policy enforcement
    in WebSockets

  - CVE-2019-13728: Fixed an out of bounds write in V8

  - CVE-2019-13729: Fixed a use after free in WebSockets

  - CVE-2019-13730: Fixed a type Confusion in V8

  - CVE-2019-13732: Fixed a use after free in WebAudio

  - CVE-2019-13734: Fixed an out of bounds write in SQLite

  - CVE-2019-13735: Fixed an out of bounds write in V8

  - CVE-2019-13764: Fixed a type Confusion in V8

  - CVE-2019-13736: Fixed an integer overflow in PDFium

  - CVE-2019-13737: Fixed an insufficient policy enforcement
    in autocomplete

  - CVE-2019-13738: Fixed an insufficient policy enforcement
    in navigation

  - CVE-2019-13739: Fixed an incorrect security UI in
    Omnibox

  - CVE-2019-13740: Fixed an incorrect security UI in
    sharing

  - CVE-2019-13741: Fixed an insufficient validation of
    untrusted input in Blink

  - CVE-2019-13742: Fixed an incorrect security UI in
    Omnibox

  - CVE-2019-13743: Fixed an incorrect security UI in
    external protocol handling

  - CVE-2019-13744: Fixed an insufficient policy enforcement
    in cookies

  - CVE-2019-13745: Fixed an insufficient policy enforcement
    in audio

  - CVE-2019-13746: Fixed an insufficient policy enforcement
    in Omnibox

  - CVE-2019-13747: Fixed an uninitialized Use in rendering

  - CVE-2019-13748: Fixed an insufficient policy enforcement
    in developer tools

  - CVE-2019-13749: Fixed an incorrect security UI in
    Omnibox

  - CVE-2019-13750: Fixed an insufficient data validation in
    SQLite

  - CVE-2019-13751: Fixed an uninitialized Use in SQLite

  - CVE-2019-13752: Fixed an out of bounds read in SQLite

  - CVE-2019-13753: Fixed an out of bounds read in SQLite

  - CVE-2019-13754: Fixed an insufficient policy enforcement
    in extensions

  - CVE-2019-13755: Fixed an insufficient policy enforcement
    in extensions

  - CVE-2019-13756: Fixed an incorrect security UI in
    printing

  - CVE-2019-13757: Fixed an incorrect security UI in
    Omnibox

  - CVE-2019-13758: Fixed an insufficient policy enforcement
    in navigation

  - CVE-2019-13759: Fixed an incorrect security UI in
    interstitials

  - CVE-2019-13761: Fixed an incorrect security UI in
    Omnibox

  - CVE-2019-13762: Fixed an insufficient policy enforcement
    in downloads

  - CVE-2019-13763: Fixed an insufficient policy enforcement
    in payments");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158982");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13764");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-79.0.3945.79-lp151.2.51.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromedriver-debuginfo-79.0.3945.79-lp151.2.51.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-79.0.3945.79-lp151.2.51.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debuginfo-79.0.3945.79-lp151.2.51.1", allowmaj:TRUE) ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"chromium-debugsource-79.0.3945.79-lp151.2.51.1", allowmaj:TRUE) ) flag++;

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
