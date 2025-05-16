#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASFIREFOX-2023-010.
##

include('compat.inc');

if (description)
{
  script_id(181940);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2021-28429",
    "CVE-2022-40674",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40961",
    "CVE-2022-40962",
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42932"
  );
  script_xref(name:"IAVA", value:"2022-A-0435-S");
  script_xref(name:"IAVA", value:"2022-A-0491-S");
  script_xref(name:"IAVA", value:"2023-A-0132-S");
  script_xref(name:"IAVA", value:"2022-A-0384-S");

  script_name(english:"Amazon Linux 2 : firefox (ALASFIREFOX-2023-010)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of firefox installed on the remote host is prior to 102.4.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2FIREFOX-2023-010 advisory.

    2023-09-27: CVE-2021-28429 was added to this advisory.

    Integer overflow vulnerability in av_timecode_make_string in libavutil/timecode.c in FFmpeg version 4.3.2,
    allows local attackers to cause a denial of service (DoS) via crafted .mov file. (CVE-2021-28429)

    A vulnerability was found in expat. With this flaw, it is possible to create a situation in which parsing
    is suspended while substituting in an internal entity so that XML_ResumeParser directly uses the
    internalEntityProcessor as its processor. If the subsequent parse includes some unclosed tags, this will
    return without calling storeRawNames to ensure that the raw versions of the tag names are stored in memory
    other than the parse buffer itself. Issues occur if the parse buffer is changed or reallocated (for
    example, if processing a file line by line), problems occur. Using this vulnerability in the doContent
    function allows an attacker to triage a denial of service or potentially arbitrary code execution.
    (CVE-2022-40674)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue that when
    injecting an HTML base element; some requests would ignore the CSP's base-uri settings and accept the
    injected element's base instead. (CVE-2022-40956)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue of inconsistent
    data in the instruction and data cache when creating wasm code, which could lead to a potentially
    exploitablecrash. (CVE-2022-40957)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue that by
    injecting a cookie with certain special characters, an attacker on a shared subdomain, which is not a
    secure context,could set and overwrite cookies from a secure context, leading to session fixation and
    other attacks. (CVE-2022-40958)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue that certain
    pages did not have their FeaturePolicy fully initialized during iframe navigation, leading to a bypass
    that leaked device permissions into untrusted subdocuments. (CVE-2022-40959)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue that concurrent
    use of the URL parser with non-UTF-8 data was not thread-safe, leading to a use-after-free problem and
    causing a potentially exploitable crash. (CVE-2022-40960)

    A stack based buffer overflow vulnerability was identified in Mozilla Firefox and Firefox ESR. This
    vulnerability occurs when the buffer being overwritten is allocated on the stack (i.e., is a local
    variable or, rarely, a parameter to a function). An attacker could cause of denial-of-service style crash
    by exploiting this vulnerability. To exploit this vulnerability, a remote, unauthenticated attacker would
    need to convince a user to visit a specially crafted website or open a malicious document.
    (CVE-2022-40961)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue of Mozilla
    developers Nika Layzell, Timothy Nikkel, Jeff Muizelaar, Sebastian Hengst, Andreas Pehrson, and the
    Mozilla Fuzzing Team reporting memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of
    these bugs showed evidence of memory corruption and the presumption that with enough effort, some have
    been exploited to run arbitrary code. (CVE-2022-40962)

    Mozilla: A same-origin policy violation could have allowed the theft of cross-origin URL entries, leaking
    the result of a redirect, via performance.getEntries(). (CVE-2022-42927)

    Mozilla: Certain types of allocations were missing annotations that, if the Garbage Collector was in a
    specific state, could have lead to memory corruption and a potentially exploitable crash. (CVE-2022-42928)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue of a website
    called window.print() causing a denial of service of the browser, which may persist beyond browser restart
    depending on the user's session restore settings. (CVE-2022-42929)

    A flaw was found in Mozilla. The Mozilla Foundation Security Advisory describes the issue of Mozilla
    developers Ashley Hale and the Mozilla Fuzzing Team, reporting memory safety bugs present in Firefox 105
    and Firefox ESR 102.3. Some of these bugs showed evidence of memory corruption and, with enough effort,
    exploited to run arbitrary code. (CVE-2022-42932)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASFIREFOX-2023-010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28429.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40674.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40957.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40958.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40961.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40962.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42932.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update firefox' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'firefox-102.4.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-102.4.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-102.4.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-102.4.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
