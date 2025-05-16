#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASPYTHON3.8-2024-016.
##

include('compat.inc');

if (description)
{
  script_id(210923);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2007-4559",
    "CVE-2021-28861",
    "CVE-2024-0397",
    "CVE-2024-0450",
    "CVE-2024-4032",
    "CVE-2024-6232",
    "CVE-2024-6923",
    "CVE-2024-7592",
    "CVE-2024-8088"
  );

  script_name(english:"Amazon Linux 2 : python38 (ALASPYTHON3.8-2024-016)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of python38 installed on the remote host is prior to 3.8.20-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2PYTHON3.8-2024-016 advisory.

    Directory traversal vulnerability in the (1) extract and (2) extractall functions in the tarfile module in
    Python allows user-assisted remote attackers to overwrite arbitrary files via a .. (dot dot) sequence in
    filenames in a TAR archive, a related issue to CVE-2001-1267. (CVE-2007-4559)

    Python 3.x through 3.10 has an open redirection vulnerability in lib/http/server.py due to no protection
    against multiple (/) at the beginning of URI path which may leads to information disclosure. NOTE: this is
    disputed by a third party because the http.server.html documentation page states Warning: http.server is
    not recommended for production. It only implements basic security checks. (CVE-2021-28861)

    A defect was discovered in the Python ssl module where there is a memoryrace condition with the
    ssl.SSLContext methods cert_store_stats() andget_ca_certs(). The race condition can be triggered if
    the methods arecalled at the same time as certificates are loaded into the SSLContext,such as during the
    TLS handshake with a certificate directory configured.This issue is fixed in CPython 3.10.14, 3.11.9,
    3.12.3, and 3.13.0a5. (CVE-2024-0397)

    An issue was found in the CPython `zipfile` module affecting versions 3.12.2, 3.11.8, 3.10.13, 3.9.18, and
    3.8.18 and prior.

    The zipfile module is vulnerable to quoted-overlap zip-bombs which exploit the zip format to create a
    zip-bomb with a high compression ratio. The fixed versions of CPython makes the zipfile module reject zip
    archives which overlap entries in the archive. (CVE-2024-0450)

    The ipaddress module contained incorrect information about whether certain IPv4 and IPv6 addresses were
    designated as globally reachable or private. This affected the is_private and is_global properties of
    the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network
    classes, where values wouldn't be returned in accordance with the latest information from the IANA
    Special-Purpose Address Registries.

    CPython 3.12.4 and 3.13.0a6 contain updated information from these registries and thus have the intended
    behavior. (CVE-2024-4032)

    There is a MEDIUM severity vulnerability affecting CPython.





    Regular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are
    vulnerable to ReDoS via specifically-crafted tar archives. (CVE-2024-6232)

    There is a MEDIUM severity vulnerability affecting CPython.

    Theemail module didn't properly quote newlines for email headers whenserializing an email message allowing
    for header injection when an emailis serialized. (CVE-2024-6923)

    There is a LOW severity vulnerability affecting CPython, specifically the'http.cookies' standard library
    module.

    When parsing cookies that contained backslashes for quoted characters inthe cookie value, the parser would
    use an algorithm with quadraticcomplexity, resulting in excess CPU resources being used while parsing
    thevalue. (CVE-2024-7592)

    There is a severity vulnerability affecting the CPython zipfilemodule.

    When iterating over names of entries in a zip archive (for example, methodsof zipfile.ZipFile like
    namelist(), iterdir(), extractall(), etc)the process can be put into an infinite loop with a
    maliciously craftedzip archive. This defect applies when reading only metadata or extractingthe contents
    of the zip archive. Programs that are not handlinguser-controlled zip archives are not affected.
    (CVE-2024-8088)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASPYTHON3.8-2024-016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2007-4559.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28861.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0397.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0450.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-4032.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-6232.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-6923.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-7592.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-8088.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update python38' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/S:N/AU:N/R:U/RE:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-4559");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28861");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-8088");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python38-tools");
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

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-python3.8"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'python38-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-debug-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-debug-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-debuginfo-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-debuginfo-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-devel-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-devel-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-libs-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-libs-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-test-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-test-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-tkinter-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-tkinter-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-tools-3.8.20-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'},
    {'reference':'python38-tools-3.8.20-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python3.8'}
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
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python38 / python38-debug / python38-debuginfo / etc");
}
