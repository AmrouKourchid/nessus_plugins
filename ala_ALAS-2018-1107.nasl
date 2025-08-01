#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1107.
#

include('compat.inc');

if (description)
{
  script_id(119466);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/17");

  script_cve_id(
    "CVE-2014-10071",
    "CVE-2014-10072",
    "CVE-2017-18205",
    "CVE-2017-18206",
    "CVE-2018-1071",
    "CVE-2018-1083",
    "CVE-2018-1100",
    "CVE-2018-7549"
  );
  script_xref(name:"ALAS", value:"2018-1107");

  script_name(english:"Amazon Linux AMI : zsh (ALAS-2018-1107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A buffer overflow flaw was found in the zsh shell symbolic link
resolver. A local, unprivileged user can create a specially crafted
directory path which leads to a buffer overflow in the context of the
user trying to do a symbolic link resolution in the aforementioned
path. If the user affected is privileged, this leads to privilege
escalation.(CVE-2017-18206)

A buffer overflow flaw was found in the zsh shell auto-complete
functionality. A local, unprivileged user can create a specially
crafted directory path which leads to code execution in the context of
the user who tries to use auto-complete to traverse the before
mentioned path. If the user affected is privileged, this leads to
privilege escalation.(CVE-2018-1083)

A NULL pointer dereference flaw was found in the code responsible for
saving hashtables of the zsh package. An attacker could use this flaw
to cause a denial of service by crashing the user
shell.(CVE-2018-7549)

A NULL pointer dereference flaw was found in the code responsible for
the cd builtin command of the zsh package. An attacker could use this
flaw to cause a denial of service by crashing the user
shell.(CVE-2017-18205)

A buffer overflow flaw was found in the zsh shell symbolic link
resolver. A local, unprivileged user can create a specially crafted
directory path which leads to a buffer overflow in the context of the
user trying to do symbolic link resolution in the aforementioned path.
An attacker could exploit this vulnerability to cause a denial of
service condition on the target.(CVE-2014-10072)

A buffer overflow flaw was found in the zsh shell check path
functionality. A local, unprivileged user can create a specially
crafted message file, which, if used to set a custom 'you have new
mail' message, leads to code execution in the context of the user who
receives the message. If the user affected is privileged, this leads
to privilege escalation.(CVE-2018-1100)

zsh through version 5.4.2 is vulnerable to a stack-based buffer
overflow in the exec.c:hashcmd() function. A local attacker could
exploit this to cause a denial of service.(CVE-2018-1071)

A buffer overflow flaw was found in the zsh shell file descriptor
redirection functionality. An attacker could use this flaw to cause a
denial of service by crashing the user shell.(CVE-2014-10071)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-1107.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update zsh' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18206");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zsh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:zsh-html");
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
if (rpm_check(release:"ALA", reference:"zsh-5.0.2-31.17.amzn1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"ALA", reference:"zsh-debuginfo-5.0.2-31.17.amzn1", allowmaj:TRUE)) flag++;
if (rpm_check(release:"ALA", reference:"zsh-html-5.0.2-31.17.amzn1", allowmaj:TRUE)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zsh / zsh-debuginfo / zsh-html");
}
