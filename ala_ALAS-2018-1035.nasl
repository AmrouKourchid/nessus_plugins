#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1035.
#

include('compat.inc');

if (description)
{
  script_id(110458);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_cve_id("CVE-2018-11233", "CVE-2018-11235");
  script_xref(name:"ALAS", value:"2018-1035");

  script_name(english:"Amazon Linux AMI : git (ALAS-2018-1035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2,
2.16.x before 2.16.4, and 2.17.x before 2.17.1, code to sanity-check
pathnames on NTFS can result in reading out-of-bounds
memory.(CVE-2018-11233)

In Git before 2.13.7, 2.14.x before 2.14.4, 2.15.x before 2.15.2,
2.16.x before 2.16.4, and 2.17.x before 2.17.1, remote code execution
can occur. With a crafted .gitmodules file, a malicious project can
execute an arbitrary script on a machine that runs 'git clone
--recurse-submodules' because submodule 'names' are obtained from this
file, and then appended to $GIT_DIR/modules, leading to directory
traversal with '../' in a name. Finally, post-checkout hooks from a
submodule are executed, bypassing the intended design in which hooks
are not obtained from a remote server.(CVE-2018-11235)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-1035.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update git' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-git-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-bzr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-hg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Git-SVN");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
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
if (rpm_check(release:"ALA", reference:"emacs-git-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-git-el-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-all-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-bzr-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-cvs-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-daemon-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-debuginfo-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-email-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-hg-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-p4-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"git-svn-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"gitweb-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-2.14.4-2.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Git-SVN-2.14.4-2.58.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-git / emacs-git-el / git / git-all / git-bzr / git-cvs / etc");
}
