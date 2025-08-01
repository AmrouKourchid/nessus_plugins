#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1118.
#

include('compat.inc');

if (description)
{
  script_id(119477);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/17");

  script_cve_id("CVE-2018-10915", "CVE-2018-10925");
  script_xref(name:"ALAS", value:"2018-1118");

  script_name(english:"Amazon Linux AMI : postgresql95 (ALAS-2018-1118)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A vulnerability was found in libpq, the default PostgreSQL client
library where libpq failed to properly reset its internal state
between connections. If an affected version of libpq were used with
'host' or 'hostaddr' connection parameters from untrusted input,
attackers could bypass client-side connection security features,
obtain access to higher privileged connections or potentially cause
other impact through SQL injection, by causing the PQescape()
functions to malfunction.(CVE-2018-10915)

It was discovered that PostgreSQL failed to properly check
authorization on certain statements involved with 'INSERT ... ON
CONFLICT DO UPDATE'. An attacker with 'CREATE TABLE' privileges could
exploit this to read arbitrary bytes server memory. If the attacker
also had certain 'INSERT' and limited 'UPDATE' privileges to a
particular table, they could exploit this to update other columns in
the same table.(CVE-2018-10925)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-1118.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update postgresql95' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10915");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-10925");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"postgresql95-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-contrib-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-debuginfo-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-devel-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-docs-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-libs-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plperl-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython26-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython27-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-server-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-static-9.5.15-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-test-9.5.15-1.80.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql95 / postgresql95-contrib / postgresql95-debuginfo / etc");
}
