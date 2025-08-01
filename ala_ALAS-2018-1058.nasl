#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1058.
#

include('compat.inc');

if (description)
{
  script_id(111702);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_cve_id(
    "CVE-2018-3615",
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-5391"
  );
  script_xref(name:"ALAS", value:"2018-1058");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2018-1058) (Foreshadow)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Fixes for L1Terminal Fault security issues :

L1 Terminal Fault-OS/ SMM :

Systems with microprocessors utilizing speculative execution and
address translations may allow unauthorized disclosure of information
residing in the L1 data cache to an attacker with local user access
via a terminal page fault and side-channel analysis.(CVE-2018-3620)

L1 Terminal Fault-VMM :

Systems with microprocessors utilizing speculative execution and
address translations may allow unauthorized disclosure of information
residing in the L1 data cache to an attacker with local user access
with guest OS privilege via a terminal page fault and side-channel
analysis.(CVE-2018-3646)

L1 Terminal Fault-SGX :

Systems with microprocessors utilizing speculative execution and Intel
SGX may allow unauthorized disclosure of information residing in the
L1 data cache from an enclave to an attacker with local user access
via side-channel analysis. AWS is not affected by CVE-2018-3615 .
There is no AWS products related to enclave systems like
SGX.(CVE-2018-3615)

Denial of service caused by a large number of IP fragments :

A denial of service attack by exhausting resources on a networked host
by sending a large number of IP fragments that can not be reassembled
by the receiver.(CVE-2018-5391)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2018-1058.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' and reboot your instance to update your
system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3615");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"ALA", reference:"kernel-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.14.62-65.117.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.14.62-65.117.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
