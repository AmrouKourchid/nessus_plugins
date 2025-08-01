#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1229 and 
# CentOS Errata and Security Advisory 2015:1229 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84771);
  script_version("2.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2015-2590",
    "CVE-2015-2601",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2628",
    "CVE-2015-2632",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    73684,
    74733,
    75784,
    75796,
    75812,
    75818,
    75823,
    75832,
    75854,
    75861,
    75867,
    75874,
    75890,
    75895
  );
  script_xref(name:"RHSA", value:"2015:1229");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"CentOS 6 / 7 : java-1.7.0-openjdk (CESA-2015:1229) (Bar Mitzvah) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated java-1.7.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2015-4760, CVE-2015-2628, CVE-2015-4731, CVE-2015-2590,
CVE-2015-4732, CVE-2015-4733)

A flaw was found in the way the Libraries component of OpenJDK
verified Online Certificate Status Protocol (OCSP) responses. An OCSP
response with no nextUpdate date specified was incorrectly handled as
having unlimited validity, possibly causing a revoked X.509
certificate to be interpreted as valid. (CVE-2015-4748)

It was discovered that the JCE component in OpenJDK failed to use
constant time comparisons in multiple cases. An attacker could
possibly use these flaws to disclose sensitive information by
measuring the time used to perform operations using these non-constant
time comparisons. (CVE-2015-2601)

A flaw was found in the RC4 encryption algorithm. When using certain
keys for RC4 encryption, an attacker could obtain portions of the
plain text from the cipher text without the knowledge of the
encryption key. (CVE-2015-2808)

Note: With this update, OpenJDK now disables RC4 TLS/SSL cipher suites
by default to address the CVE-2015-2808 issue. Refer to Red Hat
Bugzilla bug 1207101, linked to in the References section, for
additional details about this change.

A flaw was found in the way the TLS protocol composed the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenJDK
to reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Refer to Red Hat Bugzilla bug
1223211, linked to in the References section, for additional details
about this change.

It was discovered that the JNDI component in OpenJDK did not handle
DNS resolutions correctly. An attacker able to trigger such DNS errors
could cause a Java application using JNDI to consume memory and CPU
time, and possibly block further DNS resolution. (CVE-2015-4749)

Multiple information leak flaws were found in the JMX and 2D
components in OpenJDK. An untrusted Java application or applet could
use this flaw to bypass certain Java sandbox restrictions.
(CVE-2015-2621, CVE-2015-2632)

A flaw was found in the way the JSSE component in OpenJDK performed
X.509 certificate identity verification when establishing a TLS/SSL
connection to a host identified by an IP address. In certain cases,
the certificate was accepted as valid if it was issued for a host name
to which the IP address resolves rather than for the IP address.
(CVE-2015-2625)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect.");
  # https://lists.centos.org/pipermail/centos-announce/2015-July/021240.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b7c211b");
  # https://lists.centos.org/pipermail/centos-announce/2015-July/021247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e030ffe");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.7.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4760");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.85-2.6.1.3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.85-2.6.1.3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.85-2.6.1.3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.85-2.6.1.3.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.85-2.6.1.3.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-javadoc-1.7.0.85-2.6.1.2.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.85-2.6.1.2.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
}
