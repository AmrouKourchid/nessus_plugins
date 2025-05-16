#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2023 Security Advisory ALAS2023-2024-677.
##

include('compat.inc');

if (description)
{
  script_id(205110);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2024-4603", "CVE-2024-4741", "CVE-2024-5535");
  script_xref(name:"IAVA", value:"2024-A-0321-S");

  script_name(english:"Amazon Linux 2023 : openssl, openssl-devel, openssl-libs (ALAS2023-2024-677)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2023 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2023-2024-677 advisory.

    Issue summary: Checking excessively long DSA keys or parameters may be veryslow.

    Impact summary: Applications that use the functions EVP_PKEY_param_check()or EVP_PKEY_public_check() to
    check a DSA public key or DSA parameters mayexperience long delays. Where the key or parameters that are
    being checkedhave been obtained from an untrusted source this may lead to a Denial ofService.

    The functions EVP_PKEY_param_check() or EVP_PKEY_public_check() performvarious checks on DSA parameters.
    Some of those computations take a long timeif the modulus (`p` parameter) is too large.

    Trying to use a very large modulus is slow and OpenSSL will not allow usingpublic keys with a modulus
    which is over 10,000 bits in length for signatureverification. However the key and parameter check
    functions do not limitthe modulus size when performing the checks.

    An application that calls EVP_PKEY_param_check() or EVP_PKEY_public_check()and supplies a key or
    parameters obtained from an untrusted source could bevulnerable to a Denial of Service attack.

    These functions are not called by OpenSSL itself on untrusted DSA keys soonly applications that directly
    call these functions may be vulnerable.

    Also vulnerable are the OpenSSL pkey and pkeyparam command line applicationswhen using the `-check`
    option.

    The OpenSSL SSL/TLS implementation is not affected by this issue.

    The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue. (CVE-2024-4603)

    openssl: Use After Free with SSL_free_buffers (CVE-2024-4741)

    Issue summary: Calling the OpenSSL API function SSL_select_next_proto with anempty supported client
    protocols buffer may cause a crash or memory contents tobe sent to the peer.

    Impact summary: A buffer overread can have a range of potential consequencessuch as unexpected application
    beahviour or a crash. In particular this issuecould result in up to 255 bytes of arbitrary private data
    from memory being sentto the peer leading to a loss of confidentiality. However, only applicationsthat
    directly call the SSL_select_next_proto function with a 0 length list ofsupported client protocols are
    affected by this issue. This would normally neverbe a valid scenario and is typically not under attacker
    control but may occur byaccident in the case of a configuration or programming error in the
    callingapplication.

    The OpenSSL API function SSL_select_next_proto is typically used by TLSapplications that support ALPN
    (Application Layer Protocol Negotiation) or NPN(Next Protocol Negotiation). NPN is older, was never
    standardised andis deprecated in favour of ALPN. We believe that ALPN is significantly morewidely deployed
    than NPN. The SSL_select_next_proto function accepts a list ofprotocols from the server and a list of
    protocols from the client and returnsthe first protocol that appears in the server list that also appears
    in theclient list. In the case of no overlap between the two lists it returns thefirst item in the client
    list. In either case it will signal whether an overlapbetween the two lists was found. In the case where
    SSL_select_next_proto iscalled with a zero length client list it fails to notice this condition andreturns
    the memory immediately following the client list pointer (and reportsthat there was no overlap in the
    lists).

    This function is typically called from a server side application callback forALPN or a client side
    application callback for NPN. In the case of ALPN the listof protocols supplied by the client is
    guaranteed by libssl to never be zero inlength. The list of server protocols comes from the application
    and should nevernormally be expected to be of zero length. In this case if theSSL_select_next_proto
    function has been called as expected (with the listsupplied by the client passed in the client/client_len
    parameters), then theapplication will not be vulnerable to this issue. If the application hasaccidentally
    been configured with a zero length server list, and hasaccidentally passed that zero length server list in
    the client/client_lenparameters, and has additionally failed to correctly handle a no overlapresponse
    (which would normally result in a handshake failure in ALPN) then itwill be vulnerable to this problem.

    In the case of NPN, the protocol permits the client to opportunistically selecta protocol when there is no
    overlap. OpenSSL returns the first client protocolin the no overlap case in support of this. The list of
    client protocols comesfrom the application and should never normally be expected to be of zero
    length.However if the SSL_select_next_proto function is accidentally called with aclient_len of 0 then an
    invalid memory pointer will be returned instead. If theapplication uses this output as the opportunistic
    protocol then the loss ofconfidentiality will occur.

    This issue has been assessed as Low severity because applications are mostlikely to be vulnerable if they
    are using NPN instead of ALPN - but NPN is notwidely used. It also requires an application configuration
    or programming error.Finally, this issue would not typically be under attacker control making
    activeexploitation unlikely.

    The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.

    Due to the low severity of this issue we are not issuing new releases ofOpenSSL at this time. The fix will
    be included in the next releases when theybecome available. (CVE-2024-5535)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2023/ALAS-2024-677.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-4603.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-4741.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-5535.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'dnf update openssl --releasever 2023.5.20240805' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-snapsafe-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2023");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'openssl-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-debugsource-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-devel-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-libs-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-perl-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'aarch64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'openssl-snapsafe-libs-debuginfo-3.0.8-1.amzn2023.0.14', 'cpu':'x86_64', 'release':'AL-2023', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-debugsource / etc");
}
