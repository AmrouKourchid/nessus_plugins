#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2427.
##

include('compat.inc');

if (description)
{
  script_id(189350);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-32919",
    "CVE-2022-32933",
    "CVE-2022-46705",
    "CVE-2022-46725",
    "CVE-2023-32359",
    "CVE-2023-35074",
    "CVE-2023-39434",
    "CVE-2023-39928",
    "CVE-2023-40451",
    "CVE-2023-41074",
    "CVE-2023-41983",
    "CVE-2023-41993",
    "CVE-2023-42843",
    "CVE-2023-42852",
    "CVE-2023-42916",
    "CVE-2023-42917",
    "CVE-2024-23226"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/16");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/25");

  script_name(english:"Amazon Linux 2 : webkitgtk4 (ALAS-2024-2427)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of webkitgtk4 installed on the remote host is prior to 2.42.3-3. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2024-2427 advisory.

    2024-04-11: CVE-2023-42843 was added to this advisory.

    2024-03-27: CVE-2024-23226 was added to this advisory.

    Impact: Visiting a website that frames malicious content may lead to UI spoofing.

    Description: The issue was addressed with improved UI handling. (CVE-2022-32919)

    A website may be able to track the websites a user visited in Safari private browsing mode.
    (CVE-2022-32933)

    A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS Ventura 13.1, Safari 16.2. Visiting a malicious
    website may lead to address bar spoofing. (CVE-2022-46705)

    A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation.
    This issue is fixed in iOS 16.4 and iPadOS 16.4. Visiting a malicious website may lead to address bar
    spoofing. (CVE-2022-46725)

    This issue was addressed with improved redaction of sensitive information. This issue is fixed in iOS
    16.7.2 and iPadOS 16.7.2. A user's password may be read aloud by VoiceOver. (CVE-2023-32359)

    The issue was addressed with improved memory handling. This issue is fixed in tvOS 17, Safari 17, watchOS
    10, iOS 17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-35074)

    A use-after-free issue was addressed with improved memory management. This issue is fixed in iOS 17 and
    iPadOS 17, watchOS 10, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-39434)

    A use-after-free vulnerability exists in the MediaRecorder API of the WebKit GStreamer-based ports
    (WebKitGTK and WPE WebKit). A specially crafted web page can abuse this vulnerability to cause memory
    corruption and potentially arbitrary code execution. A user would need to to visit a malicious webpage to
    trigger this vulnerability. (CVE-2023-39928)

    This issue was addressed with improved iframe sandbox enforcement. This issue is fixed in Safari 17. An
    attacker with JavaScript execution may be able to execute arbitrary code. (CVE-2023-40451)

    The issue was addressed with improved checks. This issue is fixed in tvOS 17, Safari 17, watchOS 10, iOS
    17 and iPadOS 17, macOS Sonoma 14. Processing web content may lead to arbitrary code execution.
    (CVE-2023-41074)

    The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.1, Safari
    17.1, iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1. Processing web content may lead to a denial-
    of-service. (CVE-2023-41983)

    The issue was addressed with improved checks. This issue is fixed in macOS Sonoma 14, Safari 17, iOS 16.7
    and iPadOS 16.7. Processing web content may lead to arbitrary code execution. Apple is aware of a report
    that this issue may have been actively exploited against versions of iOS before iOS 16.7. (CVE-2023-41993)

    An inconsistent user interface issue was addressed with improved state management. This issue is fixed in
    iOS 16.7.2 and iPadOS 16.7.2, iOS 17.1 and iPadOS 17.1, Safari 17.1, macOS Sonoma 14.1. Visiting a
    malicious website may lead to address bar spoofing. (CVE-2023-42843)

    A logic issue was addressed with improved checks. This issue is fixed in iOS 17.1 and iPadOS 17.1, watchOS
    10.1, iOS 16.7.2 and iPadOS 16.7.2, macOS Sonoma 14.1, Safari 17.1, tvOS 17.1. Processing web content may
    lead to arbitrary code execution. (CVE-2023-42852)

    An out-of-bounds read was addressed with improved input validation. This issue is fixed in iOS 17.1.2 and
    iPadOS 17.1.2, macOS Sonoma 14.1.2, Safari 17.1.2. Processing web content may disclose sensitive
    information. Apple is aware of a report that this issue may have been exploited against versions of iOS
    before iOS 16.7.1. (CVE-2023-42916)

    A memory corruption vulnerability was addressed with improved locking. This issue is fixed in iOS 17.1.2
    and iPadOS 17.1.2, macOS Sonoma 14.1.2, Safari 17.1.2. Processing web content may lead to arbitrary code
    execution. Apple is aware of a report that this issue may have been exploited against versions of iOS
    before iOS 16.7.1. (CVE-2023-42917)

    The issue was addressed with improved memory handling. This issue is fixed in macOS Sonoma 14.4, visionOS
    1.1, iOS 17.4 and iPadOS 17.4, watchOS 10.4, tvOS 17.4. Processing web content may lead to arbitrary code
    execution. (CVE-2024-23226)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2427.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32919.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-32933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46705.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-46725.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-32359.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-35074.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39434.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-39928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-40451.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-41074.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-41983.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-41993.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-42843.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-42852.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-42916.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-42917.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-23226.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update webkitgtk4' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23226");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:webkitgtk4-jsc-devel");
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
    {'reference':'webkitgtk4-2.42.3-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-2.42.3-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-2.42.3-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.42.3-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.42.3-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-debuginfo-2.42.3-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.42.3-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.42.3-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-devel-2.42.3-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.42.3-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.42.3-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-2.42.3-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.42.3-3.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.42.3-3.amzn2.0.1', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'webkitgtk4-jsc-devel-2.42.3-3.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "webkitgtk4 / webkitgtk4-debuginfo / webkitgtk4-devel / etc");
}
