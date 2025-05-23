#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1504.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119540);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/16");

  script_cve_id("CVE-2018-11784");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2018-1504)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for tomcat to 9.0.12 fixes the following issues :

See the full changelog at:
http://tomcat.apache.org/tomcat-9.0-doc/changelog.html#Tomcat_9.0.12_(
markt)

Security issues fixed :

  - CVE-2018-11784: When the default servlet in Apache
    Tomcat returned a redirect to a directory (e.g.
    redirecting to '/foo/' when the user requested '/foo') a
    specially crafted URL could be used to cause the
    redirect to be generated to any URI of the attackers
    choice. (bsc#1110850)

This update was imported from the SUSE:SLE-15:Update update project.");
  # http://tomcat.apache.org/tomcat-9.0-doc/changelog.html#Tomcat_9.0.12_(markt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d8ffdc");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110850");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-el-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsp-2_3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-servlet-4_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"tomcat-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-admin-webapps-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-docs-webapp-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-el-3_0-api-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-embed-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-javadoc-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-jsp-2_3-api-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-jsvc-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-lib-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-servlet-4_0-api-9.0.12-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"tomcat-webapps-9.0.12-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
