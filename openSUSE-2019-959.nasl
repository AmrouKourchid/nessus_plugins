#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-959.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123388);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2018-16428", "CVE-2018-16429");

  script_name(english:"openSUSE Security Update : glib2 (openSUSE-2019-959)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for glib2 fixes the following issues :

Security issues fixed :

  - CVE-2018-16428: Do not do a NULL pointer dereference
    (crash). Avoid that, at the cost of introducing a new
    translatable error message (bsc#1107121).

  - CVE-2018-16429: Fixed out-of-bounds read vulnerability
    ing_markup_parse_context_parse() (bsc#1107116).

Non-security issue fixed :

  - various GVariant parsing issues have been resolved
    (bsc#1111499)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111499");
  script_set_attribute(attribute:"solution", value:
"Update the affected glib2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16428");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gio-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glib2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgio-fam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libglib-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgmodule-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgobject-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgthread-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"gio-branding-upstream-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-debugsource-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-devel-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-devel-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-devel-static-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-lang-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-tools-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"glib2-tools-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgio-2_0-0-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgio-2_0-0-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgio-fam-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgio-fam-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libglib-2_0-0-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libglib-2_0-0-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgmodule-2_0-0-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgmodule-2_0-0-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgobject-2_0-0-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgobject-2_0-0-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgthread-2_0-0-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgthread-2_0-0-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"glib2-devel-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"glib2-devel-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"glib2-tools-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"glib2-tools-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgio-2_0-0-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgio-2_0-0-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgio-fam-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgio-fam-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libglib-2_0-0-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libglib-2_0-0-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgmodule-2_0-0-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgobject-2_0-0-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-2.54.3-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libgthread-2_0-0-32bit-debuginfo-2.54.3-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gio-branding-upstream / glib2-debugsource / glib2-devel / etc");
}
