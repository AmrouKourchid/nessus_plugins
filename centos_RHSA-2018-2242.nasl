#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2242 and 
# CentOS Errata and Security Advisory 2018:2242 respectively.
#

include('compat.inc');

if (description)
{
  script_id(111340);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/03");

  script_cve_id("CVE-2018-2952");
  script_xref(name:"RHSA", value:"2018:2242");

  script_name(english:"CentOS 7 : java-1.8.0-openjdk (CESA-2018:2242)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Security Fix(es) :

* OpenJDK: insufficient index validation in PatternSyntaxException
getMessage () (Concurrency, 8199547) (CVE-2018-2952)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

Bug Fix(es) :

* This update applies changes from OpenJDK upstream version 8u172,
which provides a number of bug fixes over the previous version, 8u171.
(BZ# 1588364)

* OpenJDK was recently updated to support reading the system
certificate authority database (cacerts) directly. As an unintended
consequence, this removed the ability to read certificates from the
user-provided jssecacerts file. With this update, that ability is
restored by reading from that file first, if available. (BZ#1593737)");
  # https://lists.centos.org/pipermail/centos-announce/2018-July/022972.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c43a0647");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2952");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.181-3.b13.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.181-3.b13.el7_5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
