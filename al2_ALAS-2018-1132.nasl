#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1132.
#

include('compat.inc');

if (description)
{
  script_id(119786);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/15");

  script_cve_id("CVE-2018-14647");
  script_xref(name:"ALAS", value:"2018-1132");

  script_name(english:"Amazon Linux 2 : python3 (ALAS-2018-1132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Python's elementtree C accelerator failed to initialise Expat's hash
salt during initialization. This could make it easy to conduct denial
of service attacks against Expat by contructing an XML document that
would cause pathological hash collisions in Expat's internal data
structures, consuming large amounts CPU and RAM.(CVE-2018-14647)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1132.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python3' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14647");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"python3-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-debug-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-debuginfo-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-devel-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-libs-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-test-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-tkinter-3.7.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python3-tools-3.7.1-9.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3 / python3-debug / python3-debuginfo / python3-devel / etc");
}
