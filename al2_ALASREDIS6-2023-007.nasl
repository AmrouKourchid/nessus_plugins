#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASREDIS6-2023-007.
##

include('compat.inc');

if (description)
{
  script_id(182071);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2021-32626",
    "CVE-2021-32627",
    "CVE-2021-32628",
    "CVE-2021-32672",
    "CVE-2021-32675",
    "CVE-2021-32762",
    "CVE-2021-41099"
  );

  script_name(english:"Amazon Linux 2 : redis (ALASREDIS6-2023-007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of redis installed on the remote host is prior to 6.2.6-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2REDIS6-2023-007 advisory.

    Redis is an open source, in-memory database that persists on disk. In affected versions specially crafted
    Lua scripts executing in Redis can cause the heap-based Lua stack to be overflowed, due to incomplete
    checks for this condition. This can result with heap corruption and potentially remote code execution.
    This problem exists in all versions of Redis with Lua scripting support, starting from 2.6. The problem is
    fixed in versions 6.2.6, 6.0.16 and 5.0.14. For users unable to update an additional workaround to
    mitigate the problem without patching the redis-server executable is to prevent users from executing Lua
    scripts. This can be done using ACL to restrict EVAL and EVALSHA commands. (CVE-2021-32626)

    Redis is an open source, in-memory database that persists on disk. In affected versions an integer
    overflow bug in Redis can be exploited to corrupt the heap and potentially result with remote code
    execution. The vulnerability involves changing the default proto-max-bulk-len and client-query-buffer-
    limit configuration parameters to very large values and constructing specially crafted very large stream
    elements. The problem is fixed in Redis 6.2.6, 6.0.16 and 5.0.14. For users unable to upgrade an
    additional workaround to mitigate the problem without patching the redis-server executable is to prevent
    users from modifying the proto-max-bulk-len configuration parameter. This can be done using ACL to
    restrict unprivileged users from using the CONFIG SET command. (CVE-2021-32627)

    Redis is an open source, in-memory database that persists on disk. An integer overflow bug in the ziplist
    data structure used by all versions of Redis can be exploited to corrupt the heap and potentially result
    with remote code execution. The vulnerability involves modifying the default ziplist configuration
    parameters (hash-max-ziplist-entries, hash-max-ziplist-value, zset-max-ziplist-entries or zset-max-
    ziplist-value) to a very large value, and then constructing specially crafted commands to create very
    large ziplists. The problem is fixed in Redis versions 6.2.6, 6.0.16, 5.0.14. An additional workaround to
    mitigate the problem without patching the redis-server executable is to prevent users from modifying the
    above configuration parameters. This can be done using ACL to restrict unprivileged users from using the
    CONFIG SET command. (CVE-2021-32628)

    Redis is an open source, in-memory database that persists on disk. When using the Redis Lua Debugger,
    users can send malformed requests that cause the debugger's protocol parser to read data beyond the actual
    buffer. This issue affects all versions of Redis with Lua debugging support (3.2 or newer). The problem is
    fixed in versions 6.2.6, 6.0.16 and 5.0.14. (CVE-2021-32672)

    Redis is an open source, in-memory database that persists on disk. When parsing an incoming Redis Standard
    Protocol (RESP) request, Redis allocates memory according to user-specified values which determine the
    number of elements (in the multi-bulk header) and size of each element (in the bulk header). An attacker
    delivering specially crafted requests over multiple connections can cause the server to allocate
    significant amount of memory. Because the same parsing mechanism is used to handle authentication
    requests, this vulnerability can also be exploited by unauthenticated users. The problem is fixed in Redis
    versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate this problem without patching the
    redis-server executable is to block access to prevent unauthenticated users from connecting to Redis. This
    can be done in different ways: Using network access control tools like firewalls, iptables, security
    groups, etc. or Enabling TLS and requiring users to authenticate using client side certificates.
    (CVE-2021-32675)

    Redis is an open source, in-memory database that persists on disk. The redis-cli command line tool and
    redis-sentinel service may be vulnerable to integer overflow when parsing specially crafted large multi-
    bulk network replies. This is a result of a vulnerability in the underlying hiredis library which does not
    perform an overflow check before calling the calloc() heap allocation function. This issue only impacts
    systems with heap allocators that do not perform their own overflow checks. Most modern systems do and are
    therefore not likely to be affected. Furthermore, by default redis-sentinel uses the jemalloc allocator
    which is also not vulnerable. The problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14.
    (CVE-2021-32762)

    Redis is an open source, in-memory database that persists on disk. An integer overflow bug in the
    underlying string library can be used to corrupt the heap and potentially result with denial of service or
    remote code execution. The vulnerability involves changing the default proto-max-bulk-len configuration
    parameter to a very large value and constructing specially crafted network payloads or commands. The
    problem is fixed in Redis versions 6.2.6, 6.0.16 and 5.0.14. An additional workaround to mitigate the
    problem without patching the redis-server executable is to prevent users from modifying the proto-max-
    bulk-len configuration parameter. This can be done using ACL to restrict unprivileged users from using the
    CONFIG SET command. (CVE-2021-41099)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASREDIS6-2023-007.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32626.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32627.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32628.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32672.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32675.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-32762.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-41099.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update redis' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32762");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/04");
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
    {'reference':'redis-6.2.6-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-6.2.6-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-debuginfo-6.2.6-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-debuginfo-6.2.6-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-devel-6.2.6-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-devel-6.2.6-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'},
    {'reference':'redis-doc-6.2.6-1.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'redis6'}
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
      severity   : SECURITY_HOLE,
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
