#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASOPENSSL-SNAPSAFE-2023-002.
##

include('compat.inc');

if (description)
{
  script_id(182040);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2022-4304",
    "CVE-2023-0215",
    "CVE-2023-0286",
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-2650"
  );

  script_name(english:"Amazon Linux 2 : openssl-snapsafe (ALASOPENSSL-SNAPSAFE-2023-002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of openssl-snapsafe installed on the remote host is prior to 1.0.2k-24. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2OPENSSL-SNAPSAFE-2023-002 advisory.

    A timing-based side channel exists in the OpenSSL RSA Decryption implementation, which could be sufficient
    to recover a ciphertext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption, an attacker would have to be able to send a very large number of trial messages for
    decryption. This issue affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP, and RSASVE. (CVE-2022-4304)

    A use-after-free vulnerability was found in OpenSSL's BIO_new_NDEF function. The public API function
    BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is primarily used internally
    by OpenSSL to support the SMIME, CMS, and PKCS7 streaming capabilities, but it may also be called directly
    by end-user applications. The function receives a BIO from the caller, prepends a new BIO_f_asn1 filter
    BIO onto the front of it to form a BIO chain, and then returns the new head of the BIO chain to the
    caller. Under certain conditions. For example, if a CMS recipient public key is invalid, the new filter
    BIO is freed, and the function returns a NULL result indicating a failure. However, in this case, the BIO
    chain is not properly cleaned up, and the BIO passed by the caller still retains internal pointers to the
    previously freed filter BIO. If the caller then calls BIO_pop() on the BIO, a use-after-free will occur,
    possibly resulting in a crash. (CVE-2023-0215)

    A type confusion vulnerability was found in OpenSSL when OpenSSL X.400 addresses processing inside an
    X.509 GeneralName. When CRL checking is enabled (for example, the application sets the
    X509_V_FLAG_CRL_CHECK flag), this vulnerability may allow an attacker to pass arbitrary pointers to a
    memcmp call, enabling them to read memory contents or cause a denial of service. In most cases, the attack
    requires the attacker to provide both the certificate chain and CRL, of which neither needs a valid
    signature. If the attacker only controls one of these inputs, the other input must already contain an
    X.400 address as a CRL distribution point, which is uncommon. In this case, this vulnerability is likely
    only to affect applications that have implemented their own functionality for retrieving CRLs over a
    network. (CVE-2023-0286)

    A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

    Applications that use a non-default option when verifying certificates may be vulnerable to an attack from
    a malicious CA to circumvent certain checks. Invalid certificate policies in leaf certificates are
    silently ignored by OpenSSL and other certificate policy checks are skipped for that certificate. A
    malicious CA could use this to deliberately assert invalid certificate policies in order to circumvent
    policy checking on the certificate altogether. Policy processing is disabled by default but can be enabled
    by passing the `-policy' argument to the command line utilities or by calling the
    `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0465)

    The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

    Issue summary: Processing some specially crafted ASN.1 object identifiers ordata containing them may be
    very slow.

    Impact summary: Applications that use OBJ_obj2txt() directly, or use any ofthe OpenSSL subsystems OCSP,
    PKCS7/SMIME, CMS, CMP/CRMF or TS with no messagesize limit may experience notable to very long delays when
    processing thosemessages, which may lead to a Denial of Service.

    An OBJECT IDENTIFIER is composed of a series of numbers - sub-identifiers -most of which have no size
    limit.  OBJ_obj2txt() may be used to translatean ASN.1 OBJECT IDENTIFIER given in DER encoding form (using
    the OpenSSLtype ASN1_OBJECT) to its canonical numeric text form, which are thesub-identifiers of the
    OBJECT IDENTIFIER in decimal form, separated byperiods.

    When one of the sub-identifiers in the OBJECT IDENTIFIER is very large(these are sizes that are seen as
    absurdly large, taking up tens or hundredsof KiBs), the translation to a decimal number in text may take a
    very longtime.  The time complexity is O(n^2) with 'n' being the size of thesub-identifiers in bytes (*).

    With OpenSSL 3.0, support to fetch cryptographic algorithms using names /identifiers in string form was
    introduced.  This includes using OBJECTIDENTIFIERs in canonical numeric text form as identifiers for
    fetchingalgorithms.

    Such OBJECT IDENTIFIERs may be received through the ASN.1 structureAlgorithmIdentifier, which is commonly
    used in multiple protocols to specifywhat cryptographic algorithm should be used to sign or verify,
    encrypt ordecrypt, or digest passed data.

    Applications that call OBJ_obj2txt() directly with untrusted data areaffected, with any version of
    OpenSSL.  If the use is for the mere purposeof display, the severity is considered low.

    In OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME,CMS, CMP/CRMF or TS.  It also
    impacts anything that processes X.509certificates, including simple things like verifying its signature.

    The impact on TLS is relatively low, because all versions of OpenSSL have a100KiB limit on the peer's
    certificate chain.  Additionally, this onlyimpacts clients, or servers that have explicitly enabled
    clientauthentication.

    In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects,such as X.509 certificates.  This
    is assumed to not happen in such a waythat it would cause a Denial of Service, so these versions are
    considerednot affected by this issue in such a way that it would be cause for concern,and the severity is
    therefore considered low. (CVE-2023-2650)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASOPENSSL-SNAPSAFE-2023-002.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0215.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0465.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0466.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openssl-snapsafe' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0286");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-2650");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-static");
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
    {'reference':'openssl-snapsafe-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-debuginfo-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-debuginfo-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-debuginfo-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-devel-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-devel-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-devel-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-perl-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-perl-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-perl-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-static-1.0.2k-24.amzn2.0.7', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-static-1.0.2k-24.amzn2.0.7', 'cpu':'i686', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-static-1.0.2k-24.amzn2.0.7', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl-snapsafe / openssl-snapsafe-debuginfo / openssl-snapsafe-devel / etc");
}
