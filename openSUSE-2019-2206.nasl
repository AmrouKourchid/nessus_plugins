#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2206.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(129458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/22");

  script_cve_id("CVE-2019-11779");

  script_name(english:"openSUSE Security Update : mosquitto (openSUSE-2019-2206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for mosquitto fixes the following issues :

  - CVE-2019-11779: Fixed insufficient parsing of SUBSCRIBE
    packets that could lead to a stack overflow
    (bsc#1151494).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151494");
  script_set_attribute(attribute:"solution", value:
"Update the affected mosquitto packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11779");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquitto1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquitto1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquittopp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmosquittopp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mosquitto-devel");
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

if ( rpm_check(release:"SUSE15.1", reference:"libmosquitto1-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmosquitto1-debuginfo-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmosquittopp1-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libmosquittopp1-debuginfo-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-clients-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-clients-debuginfo-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-debuginfo-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-debugsource-1.5.7-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mosquitto-devel-1.5.7-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmosquitto1 / libmosquitto1-debuginfo / libmosquittopp1 / etc");
}
