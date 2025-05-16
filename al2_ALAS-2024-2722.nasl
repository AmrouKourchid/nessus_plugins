#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2722.
##

include('compat.inc');

if (description)
{
  script_id(213371);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/23");

  script_cve_id(
    "CVE-2021-28211",
    "CVE-2021-28216",
    "CVE-2021-38576",
    "CVE-2021-38578",
    "CVE-2023-45236",
    "CVE-2023-45237",
    "CVE-2024-9143",
    "CVE-2024-38796"
  );

  script_name(english:"Amazon Linux 2 : edk2 (ALAS-2024-2722)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2024-2722 advisory.

    A heap overflow in LzmaUefiDecompressGetInfo function in EDK II. (CVE-2021-28211)

    BootPerformanceTable pointer is read from an NVRAM variable in PEI. Recommend setting
    PcdFirmwarePerformanceDataTableS3Support to FALSE. (CVE-2021-28216)

    A BIOS bug in firmware for a particular PC model leaves the Platform authorization value empty. This can
    be used to permanently brick the TPM in multiple ways, as well as to non-permanently DoS the system.
    (CVE-2021-38576)

    Existing CommBuffer checks in SmmEntryPoint will not catch underflow when computing BufferSize.
    (CVE-2021-38578)

    EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. Thisvulnerability can
    be exploited by an attacker to gain unauthorizedaccess and potentially lead to a loss of Confidentiality.
    (CVE-2023-45236)

    EDK2's Network Package is susceptible to a predictable TCP Initial Sequence Number. Thisvulnerability can
    be exploited by an attacker to gain unauthorizedaccess and potentially lead to a loss of Confidentiality.
    (CVE-2023-45237)

    EDK2 contains a vulnerability in the PeCoffLoaderRelocateImage(). An Attacker may cause memory corruption
    due to an overflow via an adjacent network. A successful exploit of this vulnerability may lead to a loss
    of Confidentiality, Integrity, and/or Availability. (CVE-2024-38796)

    Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrustedexplicit values for the
    field polynomial can lead to out-of-bounds memory readsor writes.

    Impact summary: Out of bound memory writes can lead to an application crash oreven a possibility of a
    remote code execution, however, in all the protocolsinvolving Elliptic Curve Cryptography that we're aware
    of, either only namedcurves are supported, or, if explicit curve parameters are supported, theyspecify
    an X9.62 encoding of binary (GF(2^m)) curves that can't representproblematic input values. Thus the
    likelihood of existence of a vulnerableapplication is low.

    In particular, the X9.62 encoding is used for ECC keys in X.509 certificates,so problematic inputs cannot
    occur in the context of processing X.509certificates.  Any problematic use-cases would have to be using an
    exoticcurve encoding.

    The affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(),and various supporting
    BN_GF2m_*() functions.

    Applications working with exotic explicit binary (GF(2^m)) curve parameters,that make it possible to
    represent invalid field polynomials with a zeroconstant term, via the above or similar APIs, may terminate
    abruptly as aresult of reading or writing outside of array bounds.  Remote code executioncannot easily be
    ruled out.

    The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue. (CVE-2024-9143)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2722.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28211.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-28216.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38576.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-38578.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-45236.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-45237.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-38796.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-9143.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update edk2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38578");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-9143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'edk2-aarch64-20240813-296.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-debuginfo-20240813-296.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-debuginfo-20240813-296.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-ovmf-20240813-296.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20240813-296.amzn2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20240813-296.amzn2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-doc-20240813-296.amzn2', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "edk2-aarch64 / edk2-debuginfo / edk2-ovmf / etc");
}
