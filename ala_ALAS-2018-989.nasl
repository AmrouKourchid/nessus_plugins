#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-989.
#

include('compat.inc');

if (description)
{
  script_id(108850);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2018-7750");
  script_xref(name:"ALAS", value:"2018-989");

  script_name(english:"Amazon Linux AMI : python-paramiko (ALAS-2018-989)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Authentication bypass in transport.py

transport.py in the SSH server implementation of Paramiko before
1.17.6, 1.18.x before 1.18.5, 2.0.x before 2.0.8, 2.1.x before 2.1.5,
2.2.x before 2.2.3, 2.3.x before 2.3.2, and 2.4.x before 2.4.1 does
not properly check whether authentication is completed before
processing other requests, as demonstrated by channel-open. A
customized SSH client can simply skip the authentication step.
(CVE-2018-7750 )");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-989.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python-paramiko' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7750");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-paramiko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-paramiko");
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
if (rpm_check(release:"ALA", reference:"python26-paramiko-1.15.1-2.6.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-paramiko-1.15.1-2.6.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26-paramiko / python27-paramiko");
}
