#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1291.
#

include('compat.inc');

if (description)
{
  script_id(129070);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/24");

  script_cve_id("CVE-2019-9948");
  script_xref(name:"ALAS", value:"2019-1291");

  script_name(english:"Amazon Linux 2 : python (ALAS-2019-1291)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"urllib in Python 2.7.16 supports the local_file: scheme, which makes
it easier for remote attackers to bypass protection mechanisms that
blacklist file: URIs, as demonstrated by triggering a
urllib.urlopen('local_file:///etc/passwd') call. (CVE-2019-9948)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1291.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tkinter");
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
if (rpm_check(release:"AL2", reference:"python-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debug-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debuginfo-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-devel-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-libs-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-test-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-tools-2.7.16-3.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tkinter-2.7.16-3.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
}
