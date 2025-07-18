#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASREDIS6-2023-008.
##

include('compat.inc');

if (description)
{
  script_id(181948);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2021-29477", "CVE-2021-32625");

  script_name(english:"Amazon Linux 2 : redis (ALASREDIS6-2023-008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of redis installed on the remote host is prior to 6.2.4-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2REDIS6-2023-008 advisory.

    Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and
    message broker. An integer overflow bug in Redis version 6.0 or newer could be exploited using the
    `STRALGO LCS` command to corrupt the heap and potentially result with remote code execution. The problem
    is fixed in version 6.2.3 and 6.0.13. An additional workaround to mitigate the problem without patching
    the redis-server executable is to use ACL configuration to prevent clients from using the `STRALGO LCS`
    command. (CVE-2021-29477)

    Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and
    message broker. An integer overflow bug in Redis version 6.0 or newer, could be exploited using the
    STRALGO LCS command to corrupt the heap and potentially result with remote code execution. This is a
    result of an incomplete fix by CVE-2021-29477. The problem is fixed in version 6.2.4 and 6.0.14. An
    additional workaround to mitigate the problem without patching the redis-server executable is to use ACL
    configuration to prevent clients from using the STRALGO LCS command. On 64 bit systems which have the
    fixes of CVE-2021-29477 (6.2.3 or 6.0.13), it is sufficient to make sure that the proto-max-bulk-len
    config parameter is smaller than 2GB (default is 512MB). (CVE-2021-32625)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASREDIS6-2023-008.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-29477.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32625.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update redis' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:redis-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'redis-6.2.4-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-6.2.4-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-debuginfo-6.2.4-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-debuginfo-6.2.4-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-devel-6.2.4-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-devel-6.2.4-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-doc-6.2.4-1.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis / redis-debuginfo / redis-devel / etc");
}
