#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1312.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(140173);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/22");

  script_cve_id("CVE-2020-14349", "CVE-2020-14350");
  script_xref(name:"IAVB", value:"2020-B-0047-S");

  script_name(english:"openSUSE Security Update : postgresql10 (openSUSE-2020-1312)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for postgresql10 fixes the following issues :

  - update to 10.14 :

  - CVE-2020-14349, bsc#1175193: Set a secure search_path in
    logical replication walsenders and apply workers

  - CVE-2020-14350, bsc#1175194: Make contrib modules'
    installation scripts more secure.

  - https://www.postgresql.org/docs/10/release-10-14.html

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175194");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/10/release-10-14.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected postgresql10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14349");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-plpython-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:postgresql10-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-contrib-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-debugsource-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-devel-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plperl-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-plpython-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-pltcl-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-server-debuginfo-10.14-lp151.2.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"postgresql10-test-10.14-lp151.2.18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql10 / postgresql10-contrib / etc");
}
