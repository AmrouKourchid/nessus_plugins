#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1351.
#

include('compat.inc');

if (description)
{
  script_id(130603);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/15");

  script_cve_id("CVE-2019-3880");
  script_xref(name:"ALAS", value:"2019-1351");

  script_name(english:"Amazon Linux 2 : samba (ALAS-2019-1351)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A flaw was found in the way samba implemented an RPC endpoint
emulating the Windows registry service API. An unprivileged attacker
could use this flaw to create a new registry hive file anywhere they
have unix permissions which could lead to creation of a new file in
the Samba share.(CVE-2019-3880)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1351.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update samba' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3880");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:samba-winbind-modules");
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
if (rpm_check(release:"AL2", reference:"ctdb-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ctdb-tests-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libsmbclient-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libsmbclient-devel-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libwbclient-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libwbclient-devel-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-client-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-client-libs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-common-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-common-libs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-common-tools-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-dc-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-dc-libs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-debuginfo-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-devel-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-krb5-printing-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-libs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-pidl-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-python-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-python-test-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-test-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-test-libs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"samba-vfs-glusterfs-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-winbind-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-winbind-clients-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-winbind-krb5-locator-4.9.1-6.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"samba-winbind-modules-4.9.1-6.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-tests / libsmbclient / libsmbclient-devel / libwbclient / etc");
}
