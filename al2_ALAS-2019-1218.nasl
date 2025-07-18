#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1218.
#

include('compat.inc');

if (description)
{
  script_id(125601);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");
  script_xref(name:"ALAS", value:"2019-1218");

  script_name(english:"Amazon Linux 2 : freeradius (ALAS-2019-1218)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"FreeRADIUS mishandles the 'each participant verifies that the received
scalar is within a range, and that the received group element is a
valid point on the curve being used' protection mechanism, aka a
'Dragonblood' issue, a similar issue to CVE-2019-9498 and
CVE-2019-9499 .(CVE-2019-11235)

FreeRADIUS before 3.0.19 does not prevent use of reflection for
authentication spoofing, aka a 'Dragonblood' issue, a similar issue to
CVE-2019-9497 .(CVE-2019-11234)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1218.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update freeradius' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11235");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-unixODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:freeradius-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"freeradius-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-debuginfo-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-devel-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-doc-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-krb5-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-ldap-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-mysql-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-perl-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-postgresql-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-python-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-sqlite-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-unixODBC-3.0.13-10.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"freeradius-utils-3.0.13-10.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius / freeradius-debuginfo / freeradius-devel / etc");
}
