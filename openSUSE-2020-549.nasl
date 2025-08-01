#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-549.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(136009);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/14");

  script_cve_id("CVE-2020-11722");

  script_name(english:"openSUSE Security Update : crawl (openSUSE-2020-549)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for crawl fixes the following issues :

  - CVE-2020-11722: Fixed a remote code evaluation issue
    with lua loadstring (boo#1169381)

Update to version 0.24.0

  - Vampire species simplified

  - Thrown weapons streamlined

  - Fedhas reimagined

  - Sif Muna reworked

Update to version 0.23.2

  - Trap system overhaul

  - New Gauntlet portal to replace Labyrinths

  - Nemelex Xobeh rework

  - Nine unrandarts reworked and the new 'Rift' unrandart
    added

  - Support for seeded dungeon play

  - build requires python and python-pyYAML

Update to 0.22.0

  - Player ghosts now only appear in sealed ghost vaults

  - New spell library interface

  - User interface revamp for Tiles and WebTiles");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169381");
  script_set_attribute(attribute:"solution", value:
"Update the affected crawl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11722");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crawl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crawl-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crawl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crawl-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crawl-sdl-debuginfo");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"crawl-0.24.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crawl-data-0.24.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crawl-debugsource-0.24.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crawl-sdl-0.24.0-lp151.3.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"crawl-sdl-debuginfo-0.24.0-lp151.3.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "crawl / crawl-data / crawl-debugsource / crawl-sdl / etc");
}
