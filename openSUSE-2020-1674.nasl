#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1674.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(141529);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/15");

  script_cve_id("CVE-2020-24368");

  script_name(english:"openSUSE Security Update : icingaweb2 (openSUSE-2020-1674)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for icingaweb2 fixes the following issues :

  - icingaweb2 was updated to 2.7.4

  - CVE-2020-24368: Fixed a path Traversal which could have
    allowed an attacker to access arbitrary files which are
    readable by the process running (boo#1175530).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175530");
  script_set_attribute(attribute:"solution", value:
"Update the affected icingaweb2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24368");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingacli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-HTMLPurifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-JShrink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-Parsedown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-dompdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-lessphp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icingaweb2-vendor-zf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php-Icinga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"icingacli-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-common-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-HTMLPurifier-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-JShrink-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-Parsedown-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-dompdf-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-lessphp-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"icingaweb2-vendor-zf1-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php-Icinga-2.7.4-lp151.6.8.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingacli-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-common-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-HTMLPurifier-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-JShrink-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-Parsedown-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-dompdf-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-lessphp-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"icingaweb2-vendor-zf1-2.7.4-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"php-Icinga-2.7.4-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icingacli / icingaweb2 / icingaweb2-common / etc");
}
