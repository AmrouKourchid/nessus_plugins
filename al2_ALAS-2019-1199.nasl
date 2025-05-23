#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1199.
#

include('compat.inc');

if (description)
{
  script_id(124305);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2019-3855",
    "CVE-2019-3856",
    "CVE-2019-3857",
    "CVE-2019-3863"
  );
  script_xref(name:"ALAS", value:"2019-1199");

  script_name(english:"Amazon Linux 2 : libssh2 (ALAS-2019-1199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An integer overflow flaw, which could lead to an out of bounds write,
was discovered in libssh2 in the way keyboard prompt requests are
parsed. A remote attacker who compromises a SSH server may be able to
execute code on the client system when a user connects to the
server.(CVE-2019-3856)

An integer overflow flaw which could lead to an out of bounds write
was discovered in libssh2 in the way packets are read from the server.
A remote attacker who compromises a SSH server may be able to execute
code on the client system when a user connects to the
server.(CVE-2019-3855)

A vulnerability was found in in libssh2 where a server could send a
multiple keyboard interactive response messages whose total length are
greater than unsigned char max characters. This value is used as an
index to copy memory causing in an out of bounds memory write
error.(CVE-2019-3863)

An integer overflow flaw which could lead to an out of bounds write
was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets
with an exit signal are parsed. A remote attacker who compromises a
SSH server may be able to execute code on the client system when a
user connects to the server.(CVE-2019-3857)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1199.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update libssh2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3855");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3863");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libssh2-docs");
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
if (rpm_check(release:"AL2", reference:"libssh2-1.4.3-12.amzn2.2")) flag++;
if (rpm_check(release:"AL2", reference:"libssh2-debuginfo-1.4.3-12.amzn2.2")) flag++;
if (rpm_check(release:"AL2", reference:"libssh2-devel-1.4.3-12.amzn2.2")) flag++;
if (rpm_check(release:"AL2", reference:"libssh2-docs-1.4.3-12.amzn2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2 / libssh2-debuginfo / libssh2-devel / libssh2-docs");
}
