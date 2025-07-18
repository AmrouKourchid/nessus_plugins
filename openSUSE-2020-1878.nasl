#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1878.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142838);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id(
    "CVE-2020-17498",
    "CVE-2020-25862",
    "CVE-2020-25863",
    "CVE-2020-25866"
  );

  script_name(english:"openSUSE Security Update : wireshark (openSUSE-2020-1878)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for wireshark fixes the following issues :

  - Update to wireshark 3.2.7 :

  - CVE-2020-25863: MIME Multipart dissector crash
    (bsc#1176908)

  - CVE-2020-25862: TCP dissector crash (bsc#1176909)

  - CVE-2020-25866: BLIP dissector crash (bsc#1176910)

  - CVE-2020-17498: Kafka dissector crash (bsc#1175204)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176910");
  script_set_attribute(attribute:"solution", value:
"Update the affected wireshark packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25866");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwireshark13-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwiretap10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwsutil11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-ui-qt-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"libwireshark13-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwireshark13-debuginfo-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap10-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwiretap10-debuginfo-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil11-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwsutil11-debuginfo-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debuginfo-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-debugsource-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-devel-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-3.2.7-lp151.2.15.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"wireshark-ui-qt-debuginfo-3.2.7-lp151.2.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwireshark13 / libwireshark13-debuginfo / libwiretap10 / etc");
}
