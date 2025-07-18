#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1317.
#

include('compat.inc');

if (description)
{
  script_id(130610);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/15");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203");
  script_xref(name:"ALAS", value:"2019-1317");

  script_name(english:"Amazon Linux AMI : subversion (ALAS-2019-1317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In Apache Subversion versions up to and including 1.9.10, 1.10.4,
1.12.0, Subversion's svnserve server process may exit when a
well-formed read-only request produces a particular answer. This can
lead to disruption for users of the server.(CVE-2018-11782)

In Apache Subversion versions up to and including 1.9.10, 1.10.4,
1.12.0, Subversion's svnserve server process may exit when a client
sends certain sequences of protocol commands. This can lead to
disruption for users of the server.(CVE-2019-0203)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2019-1317.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update subversion' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
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
if (rpm_check(release:"ALA", reference:"mod24_dav_svn-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python26-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python27-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.9.7-1.60.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.9.7-1.60.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_dav_svn / subversion / subversion-debuginfo / etc");
}
