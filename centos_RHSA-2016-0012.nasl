#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0012 and 
# CentOS Errata and Security Advisory 2016:0012 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87785);
  script_version("2.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2015-7575");
  script_xref(name:"RHSA", value:"2016:0012");

  script_name(english:"CentOS 6 / 7 : gnutls (CESA-2016:0012) (SLOTH)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnutls packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

A flaw was found in the way TLS 1.2 could use the MD5 hash function
for signing ServerKeyExchange and Client Authentication packets during
a TLS handshake. A man-in-the-middle attacker able to force a TLS
connection to use the MD5 hash function could use this flaw to conduct
collision attacks to impersonate a TLS server or an authenticated TLS
client. (CVE-2015-7575)

All gnutls users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. For the update
to take effect, all applications linked to the GnuTLS library must be
restarted."
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-January/021596.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d37fe5fb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2016-January/021600.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbe9e6a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7575");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-dane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"gnutls-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-devel-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-guile-2.8.5-19.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnutls-utils-2.8.5-19.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-c++-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-dane-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-devel-3.3.8-14.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gnutls-utils-3.3.8-14.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-c++ / gnutls-dane / gnutls-devel / gnutls-guile / etc");
}
