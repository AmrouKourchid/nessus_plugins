#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1206.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118249);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/30");

  script_cve_id(
    "CVE-2015-8010",
    "CVE-2016-0726",
    "CVE-2016-10089",
    "CVE-2016-8641"
  );

  script_name(english:"openSUSE Security Update : icinga (openSUSE-2018-1206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for icinga fixes the following issues :

Update to 1.14.0

  - CVE-2015-8010: Fixed XSS in the icinga classic UI
    (boo#952777)

  - CVE-2016-8641 / CVE-2016-10089: fixed a possible symlink
    attack for files/dirs created by root (boo#1011630 and
    boo#1018047)

  - CVE-2016-0726: removed the pre-configured administrative
    account with fixed password for the WebUI - (boo#961115)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961115");
  script_set_attribute(attribute:"solution", value:
"Update the affected icinga packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-idoutils-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-downtimes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-plugins-eventhandlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icinga-www-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monitoring-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"icinga-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-debuginfo-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-debugsource-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-devel-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-idoutils-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-idoutils-debuginfo-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-idoutils-mysql-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-idoutils-oracle-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-idoutils-pgsql-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-plugins-downtimes-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-plugins-eventhandlers-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-www-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-www-config-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"icinga-www-debuginfo-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"monitoring-tools-1.14.0-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"monitoring-tools-debuginfo-1.14.0-8.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icinga / icinga-debuginfo / icinga-debugsource / icinga-devel / etc");
}
