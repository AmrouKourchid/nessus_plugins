#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2290 and 
# CentOS Errata and Security Advisory 2019:2290 respectively.
#

include('compat.inc');

if (description)
{
  script_id(128385);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");
  script_xref(name:"RHSA", value:"2019:2290");

  script_name(english:"CentOS 7 : libsolv (CESA-2019:2290)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for libsolv is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The libsolv packages provide a library for resolving package
dependencies using a satisfiability algorithm.

Security Fix(es) :

* libsolv: NULL pointer dereference in function testcase_read
(CVE-2018-20532)

* libsolv: NULL pointer dereference in function
testcase_str2dep_complex (CVE-2018-20533)

* libsolv: illegal address access in pool_whatprovides in src/pool.h
(CVE-2018-20534)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005963.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b874ae8f");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsolv packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsolv-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-solv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsolv-0.6.34-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsolv-demo-0.6.34-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsolv-devel-0.6.34-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libsolv-tools-0.6.34-4.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-solv-0.6.34-4.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsolv / libsolv-demo / libsolv-devel / libsolv-tools / etc");
}
