#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-990.
#

include('compat.inc');

if (description)
{
  script_id(108851);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2018-1058");
  script_xref(name:"ALAS", value:"2018-990");

  script_name(english:"Amazon Linux AMI : postgresql93 / postgresql94,postgresql95,postgresql96 (ALAS-2018-990)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Uncontrolled search path element in pg_dump and other client
applications

A flaw was found in the way Postgresql allowed a user to modify the
behavior of a query for other users. An attacker with a user account
could use this flaw to execute code with the permissions of superuser
in the database. (CVE-2018-1058)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-990.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql93' to update your system.

Run 'yum update postgresql94' to update your system.

Run 'yum update postgresql95' to update your system.

Run 'yum update postgresql96' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql96-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 Tenable Network Security, Inc.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"postgresql93-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-contrib-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-debuginfo-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-devel-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-docs-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-libs-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plperl-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython26-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython27-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-pltcl-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-server-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-test-9.3.22-1.70.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-contrib-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-debuginfo-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-devel-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-docs-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-libs-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plperl-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython26-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython27-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-server-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-test-9.4.17-1.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-contrib-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-debuginfo-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-devel-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-docs-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-libs-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plperl-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython26-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython27-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-server-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-static-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-test-9.5.12-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-contrib-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-debuginfo-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-devel-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-docs-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-libs-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-plperl-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-plpython26-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-plpython27-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-server-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-static-9.6.8-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql96-test-9.6.8-1.80.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql93 / postgresql93-contrib / postgresql93-debuginfo / etc");
}
