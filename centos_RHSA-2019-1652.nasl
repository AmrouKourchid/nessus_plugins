#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1652 and 
# CentOS Errata and Security Advisory 2019:1652 respectively.
#

include('compat.inc');

if (description)
{
  script_id(126480);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id(
    "CVE-2019-3855",
    "CVE-2019-3856",
    "CVE-2019-3857",
    "CVE-2019-3863"
  );
  script_xref(name:"RHSA", value:"2019:1652");

  script_name(english:"CentOS 6 : libssh2 (CESA-2019:1652)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for libssh2 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libssh2 packages provide a library that implements the SSH2
protocol.

Security Fix(es) :

* libssh2: Integer overflow in transport read resulting in out of
bounds write (CVE-2019-3855)

* libssh2: Integer overflow in keyboard interactive handling resulting
in out of bounds write (CVE-2019-3856)

* libssh2: Integer overflow in SSH packet processing channel resulting
in out of bounds write (CVE-2019-3857)

* libssh2: Integer overflow in user authenticate keyboard interactive
allows out-of-bounds writes (CVE-2019-3863)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  # https://lists.centos.org/pipermail/centos-announce/2019-July/023349.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26c9a39a");
  script_set_attribute(attribute:"solution", value:
"Update the affected libssh2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3855");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"libssh2-1.4.2-3.el6_10.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libssh2-devel-1.4.2-3.el6_10.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libssh2-docs-1.4.2-3.el6_10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2 / libssh2-devel / libssh2-docs");
}
