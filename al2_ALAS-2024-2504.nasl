#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2504.
##

include('compat.inc');

if (description)
{
  script_id(192203);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_name(english:"Amazon Linux 2 : rust (ALAS-2024-2504)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of rust installed on the remote host is prior to 1.68.2-1. It is, therefore, affected by a vulnerability as
referenced in the ALAS2-2024-2504 advisory.

    RUSTSEC-2024-0006 NOTE: https://rustsec.org/advisories/RUSTSEC-2024-0006.html NOTE:
    https://github.com/comex/rust-shlex/security/advisories/GHSA-r7qv-8r2h-pg27

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2504.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update rust' to update your system.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-debugger-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rust-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rustfmt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cargo-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cargo-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clippy-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analysis-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analyzer-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-analyzer-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debugger-common-1.68.2-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-debuginfo-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-doc-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-gdb-1.68.2-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-src-1.68.2-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-std-static-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rust-toolset-1.68.2-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.68.2-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rustfmt-1.68.2-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cargo / clippy / rust / etc");
}
