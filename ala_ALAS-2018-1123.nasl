#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1123.
#

include('compat.inc');

if (description)
{
  script_id(124199);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2018-10906");
  script_xref(name:"ALAS", value:"2018-1123");

  script_name(english:"Amazon Linux AMI : fuse (ALAS-2018-1123)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A vulnerability was discovered in fuse. When SELinux is active,
fusermount is vulnerable to a restriction bypass. This allows non-root
users to mount a FUSE file system with the 'allow_other' mount option
regardless of whether 'user_allow_other' is set in the fuse
configuration. An attacker may use this flaw to mount a FUSE file
system, accessible by other users, and trick them into accessing files
on that file system, possibly causing Denial of Service or other
unspecified effects. (CVE-2018-10906)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-1123.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update fuse' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10906");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fuse-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:fuse-libs");
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
if (rpm_check(release:"ALA", reference:"fuse-2.9.4-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"fuse-debuginfo-2.9.4-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"fuse-devel-2.9.4-1.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"fuse-libs-2.9.4-1.18.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fuse / fuse-debuginfo / fuse-devel / fuse-libs");
}
