#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1237.
#

include('compat.inc');

if (description)
{
  script_id(127065);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/08");

  script_cve_id("CVE-2019-11037");
  script_xref(name:"ALAS", value:"2019-1237");

  script_name(english:"Amazon Linux AMI : php54-pecl-imagick / php55-pecl-imagick,php56-pecl-imagick,php70-pecl-imagick,php71-pecl-imagick,php72-pecl-imagick (ALAS-2019-1237)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In PHP imagick extension, writing to an array of values in
ImagickKernel::fromMatrix() function did not check that the address
will be within the allocated array. This could lead to out of bounds
write to memory if the function is called with the data controlled by
untrusted party. (CVE-2019-11037)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2019-1237.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update php54-pecl-imagick' to update your system.

Run 'yum update php55-pecl-imagick' to update your system.

Run 'yum update php56-pecl-imagick' to update your system.

Run 'yum update php70-pecl-imagick' to update your system.

Run 'yum update php71-pecl-imagick' to update your system.

Run 'yum update php72-pecl-imagick' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php54-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php54-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php55-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php56-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php70-pecl-imagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php71-pecl-imagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pecl-imagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:php72-pecl-imagick-devel");
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
if (rpm_check(release:"ALA", reference:"php54-pecl-imagick-3.4.4-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php54-pecl-imagick-debuginfo-3.4.4-1.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pecl-imagick-3.4.4-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php55-pecl-imagick-debuginfo-3.4.4-1.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pecl-imagick-3.4.4-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php56-pecl-imagick-debuginfo-3.4.4-1.15.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pecl-imagick-3.4.4-1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pecl-imagick-debuginfo-3.4.4-1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php70-pecl-imagick-devel-3.4.4-1.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pecl-imagick-3.4.4-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pecl-imagick-debuginfo-3.4.4-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php71-pecl-imagick-devel-3.4.4-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pecl-imagick-3.4.4-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pecl-imagick-debuginfo-3.4.4-1.9.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"php72-pecl-imagick-devel-3.4.4-1.9.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php54-pecl-imagick / php54-pecl-imagick-debuginfo / etc");
}
