#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-544.
##

include('compat.inc');

if (description)
{
  script_id(191606);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2024-21890",
    "CVE-2024-21891",
    "CVE-2024-21892",
    "CVE-2024-21896",
    "CVE-2024-22017",
    "CVE-2024-22019",
    "CVE-2024-22025",
    "CVE-2024-24758"
  );

  script_name(english:"Amazon Linux 2023 : nodejs20, nodejs20-devel, nodejs20-full-i18n (ALAS2023-2024-544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-544 advisory.

    2024-03-13: CVE-2024-22025 was added to this advisory.

    The Node.js Permission Model does not clarify in the documentation that wildcards should be only used as
    the last character of a file path.This misleading documentation affects all users using the experimental
    permission model in active release lines: 20.x and 21.x.Please note that at the time this CVE was issued,
    the permission model is an experimental feature of Node.js. (CVE-2024-21890)

    NOTE: https://nodejs.org/en/blog/vulnerability/february-2024-security-releases/#multiple-permission-model-
    bypasses-due-to-improper-path-traversal-sequence-sanitization-cve-2024-21891---medium (CVE-2024-21891)

    A flaw was found in Node.js. On Linux, Node.js ignores certain environment variables if they have been set
    by an unprivileged user while the process is running with elevated privileges, with the exception of
    CAP_NET_BIND_SERVICE. Due to a bug in the implementation of this exception, Node.js incorrectly applies
    this exception even when other capabilities have been set. This may allow unprivileged users to inject
    code that inherits the processes elevated privileges. (CVE-2024-21892)

    NOTE: https://nodejs.org/en/blog/vulnerability/february-2024-security-releases/#path-traversal-by-monkey-
    patching-buffer-internals-cve-2024-21896---high (CVE-2024-21896)

    NOTE: https://nodejs.org/en/blog/vulnerability/february-2024-security-releases/#setuid-does-not-drop-all-
    privileges-due-to-io_uring-cve-2024-22017---high (CVE-2024-22017)

    A flaw was found in Node.js due to a lack of safeguards on chunk extension bytes. The server may read an
    unbounded number of bytes from a single connection, which can allow an attacker to send a specially
    crafted HTTP request with chunked encoding, leading to resource exhaustion and a denial of service.
    (CVE-2024-22019)

    NOTE: https://nodejs.org/en/blog/release/v18.19.1NOTE:
    https://github.com/nodejs/node/commit/f31d47e135973746c4f490d5eb635eded8bb3dda (v18.x)NOTE:
    https://github.com/nodejs/node/commit/9052ef43dc2d1b0db340591a9bc9e45a25c01d90 (main) (CVE-2024-22025)

    Undici is an HTTP/1.1 client, written from scratch for Node.js. Undici already cleared Authorization
    headers on cross-origin redirects, but did not clear `Proxy-Authentication` headers. This issue has been
    patched in versions 5.28.3 and 6.6.1. Users are advised to upgrade. There are no known workarounds for
    this vulnerability. (CVE-2024-24758)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-544.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21890.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21891.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21892.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-21896.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-22017.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-22019.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-22025.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-24758.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update nodejs20 --releasever 2023.3.20240304' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-full-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nodejs20-npm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:v8-11.3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "-2023")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2023", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'nodejs20-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-debuginfo-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-debuginfo-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-debugsource-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-debugsource-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-devel-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-devel-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-docs-20.11.1-1.amzn2023.0.1', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-full-i18n-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-full-i18n-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-libs-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-libs-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-libs-debuginfo-20.11.1-1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-libs-debuginfo-20.11.1-1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-npm-10.2.4-1.20.11.1.1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nodejs20-npm-10.2.4-1.20.11.1.1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-11.3-devel-11.3.244.8-1.20.11.1.1.amzn2023.0.1', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'v8-11.3-devel-11.3.244.8-1.20.11.1.1.amzn2023.0.1', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs20 / nodejs20-debuginfo / nodejs20-debugsource / etc");
}
