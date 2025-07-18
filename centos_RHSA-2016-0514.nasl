#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0514 and 
# CentOS Errata and Security Advisory 2016:0514 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90159);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2016-0636");
  script_xref(name:"RHSA", value:"2016:0514");

  script_name(english:"CentOS 6 : java-1.8.0-openjdk (CESA-2016:0514)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-openjdk is now available for Red Hat
Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.8.0-openjdk packages contain the latest version of the Open
Java Development Kit (OpenJDK), OpenJDK 8. These packages provide a
fully compliant implementation of Java SE 8.

Security Fix(es) :

* An improper type safety check was discovered in the Hotspot
component. An untrusted Java application or applet could use this flaw
to bypass Java Sandbox restrictions. (CVE-2016-0636)"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-March/021773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92c2addf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0636");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-debug-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-1.8.0.77-0.b03.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.77-0.b03.el6_7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc");
}
