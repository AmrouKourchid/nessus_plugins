#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1311.
#

include('compat.inc');

if (description)
{
  script_id(129793);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2018-19208");
  script_xref(name:"ALAS", value:"2019-1311");

  script_name(english:"Amazon Linux 2 : libwpd (ALAS-2019-1311)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In libwpd 0.10.2, there is a NULL pointer dereference in the function
WP6ContentListener::defineTable in WP6ContentListener.cpp that will
lead to a denial of service attack. This is related to
WPXTable.h.(CVE-2018-19208)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1311.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libwpd' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19208");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwpd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwpd-tools");
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
if (rpm_check(release:"AL2", reference:"libwpd-0.10.0-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libwpd-debuginfo-0.10.0-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libwpd-devel-0.10.0-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libwpd-doc-0.10.0-2.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libwpd-tools-0.10.0-2.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwpd / libwpd-debuginfo / libwpd-devel / libwpd-doc / etc");
}
