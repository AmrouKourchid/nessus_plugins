#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-698.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(136885);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-10030", "CVE-2020-10995", "CVE-2020-12244");

  script_name(english:"openSUSE Security Update : pdns-recursor (openSUSE-2020-698)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for pdns-recursor fixes the following issues :

  - update to 4.1.16

  - fixes an issue where records in the answer section of a
    NXDOMAIN response lacking an SOA were not properly
    validated (CVE-2020-12244, boo#1171553)

  - fixes an issue where invalid hostname on the server can
    result in disclosure of invalid memory (CVE-2020-10030,
    boo#1171553)

  - fixes an issue in the DNS protocol has been found that
    allows malicious parties to use recursive DNS services
    to attack third party authoritative name servers
    (CVE-2020-10995, boo#1171553)

For details see
https://doc.powerdns.com/recursor/changelog/4.1.html#change-4.1.16");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171553");
  script_set_attribute(attribute:"see_also", value:"https://doc.powerdns.com/recursor/changelog/4.1.html#change-4.1.16");
  script_set_attribute(attribute:"solution", value:
"Update the affected pdns-recursor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pdns-recursor-debugsource");
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

if ( rpm_check(release:"SUSE15.1", reference:"pdns-recursor-4.1.12-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-recursor-debuginfo-4.1.12-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pdns-recursor-debugsource-4.1.12-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pdns-recursor / pdns-recursor-debuginfo / pdns-recursor-debugsource");
}
