#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1180.
#

include('compat.inc');

if (description)
{
  script_id(123088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

  script_cve_id("CVE-2018-18311");
  script_xref(name:"ALAS", value:"2019-1180");

  script_name(english:"Amazon Linux AMI : perl (ALAS-2019-1180)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Perl has a buffer overflow via a crafted regular expression that
triggers invalid write operations. (CVE-2018-18311)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2019-1180.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update perl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18311");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"perl-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CPAN-1.9800-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-CBuilder-0.28.2.6-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-Embed-1.30-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-Install-1.58-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Zlib-1.10-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Locale-Maketext-Simple-0.21-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-CoreList-2.76.02-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Loaded-0.08-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Object-Accessor-0.42-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Package-Constants-0.02-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Pod-Escapes-1.04-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Time-Piece-1.20.1-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-core-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-debuginfo-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-devel-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-libs-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-macros-5.16.3-294.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-tests-5.16.3-294.43.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CPAN / perl-ExtUtils-CBuilder / perl-ExtUtils-Embed / etc");
}
