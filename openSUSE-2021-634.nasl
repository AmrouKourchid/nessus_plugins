#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-634.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149573);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/01");

  script_cve_id("CVE-2021-25900");

  script_name(english:"openSUSE Security Update : librsvg (openSUSE-2021-634)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for librsvg fixes the following issues :

  - librsvg was updated to 2.46.5 :

  - Update dependent crates that had security
    vulnerabilities: smallvec to 0.6.14 - RUSTSEC-2018-0003
    - CVE-2021-25900 (bsc#1183403)

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183403");
  script_set_attribute(attribute:"solution", value:
"Update the affected librsvg packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdk-pixbuf-loader-rsvg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librsvg-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-convert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-convert-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rsvg-thumbnailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Rsvg-2_0");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-loader-rsvg-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"gdk-pixbuf-loader-rsvg-debuginfo-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librsvg-2-2-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librsvg-2-2-debuginfo-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librsvg-debugsource-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librsvg-devel-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"librsvg-lang-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rsvg-convert-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rsvg-convert-debuginfo-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"rsvg-thumbnailer-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Rsvg-2_0-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"gdk-pixbuf-loader-rsvg-32bit-debuginfo-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"librsvg-2-2-32bit-2.46.5-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"librsvg-2-2-32bit-debuginfo-2.46.5-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf-loader-rsvg / gdk-pixbuf-loader-rsvg-debuginfo / etc");
}
