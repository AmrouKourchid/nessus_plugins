#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(193927);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id(
    "CVE-2023-2975",
    "CVE-2023-3446",
    "CVE-2023-3817",
    "CVE-2023-5363",
    "CVE-2023-5678"
  );
  script_xref(name:"IAVA", value:"2023-A-0398-S");
  script_xref(name:"IAVA", value:"2023-A-0582-S");
  script_xref(name:"IAVA", value:"2024-A-0121-S");

  script_name(english:"CentOS 9 : openssl-3.0.7-25.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openssl-3.0.7-25.el9 build changelog.

  - Issue summary: The AES-SIV cipher implementation contains a bug that causes it to ignore empty associated
    data entries which are unauthenticated as a consequence. Impact summary: Applications that use the AES-SIV
    algorithm and want to authenticate empty data entries as associated data can be mislead by removing adding
    or reordering such empty entries as these are ignored by the OpenSSL implementation. We are currently
    unaware of any such applications. The AES-SIV algorithm allows for authentication of multiple associated
    data entries along with the encryption. To authenticate empty data the application has to call
    EVP_EncryptUpdate() (or EVP_CipherUpdate()) with NULL pointer as the output buffer and 0 as the input
    buffer length. The AES-SIV implementation in OpenSSL just returns success for such a call instead of
    performing the associated data authentication operation. The empty data thus will not be authenticated. As
    this issue does not affect non-empty associated data authentication and we expect it to be rare for an
    application to use empty associated data entries this is qualified as Low severity issue. (CVE-2023-2975)

  - Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary:
    Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key
    or DH parameters may experience long delays. Where the key or parameters that are being checked have been
    obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs
    various checks on DH parameters. One of those checks confirms that the modulus ('p' parameter) is not too
    large. Trying to use a very large modulus is slow and OpenSSL will not normally use a modulus which is
    over 10,000 bits in length. However the DH_check() function checks numerous aspects of the key or
    parameters that have been supplied. Some of those checks use the supplied modulus value even if it has
    already been found to be too large. An application that calls DH_check() and supplies a key or parameters
    obtained from an untrusted source could be vulernable to a Denial of Service attack. The function
    DH_check() is itself called by a number of other OpenSSL functions. An application calling any of those
    other functions may similarly be affected. The other functions affected by this are DH_check_ex() and
    EVP_PKEY_param_check(). Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications
    when using the '-check' option. The OpenSSL SSL/TLS implementation is not affected by this issue. The
    OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue. (CVE-2023-3446)

  - Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary:
    Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key
    or DH parameters may experience long delays. Where the key or parameters that are being checked have been
    obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs
    various checks on DH parameters. After fixing CVE-2023-3446 it was discovered that a large q parameter
    value can also trigger an overly long computation during some of these checks. A correct q value, if
    present, cannot be larger than the modulus p parameter, thus it is unnecessary to perform these checks if
    q is larger than p. An application that calls DH_check() and supplies a key or parameters obtained from an
    untrusted source could be vulnerable to a Denial of Service attack. The function DH_check() is itself
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check().
    Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the -check
    option. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS
    providers are not affected by this issue. (CVE-2023-3817)

  - Issue summary: A bug has been identified in the processing of key and initialisation vector (IV) lengths.
    This can lead to potential truncation or overruns during the initialisation of some symmetric ciphers.
    Impact summary: A truncation in the IV can result in non-uniqueness, which could result in loss of
    confidentiality for some cipher modes. When calling EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() or
    EVP_CipherInit_ex2() the provided OSSL_PARAM array is processed after the key and IV have been
    established. Any alterations to the key length, via the keylen parameter or the IV length, via the
    ivlen parameter, within the OSSL_PARAM array will not take effect as intended, potentially causing
    truncation or overreading of these values. The following ciphers and cipher modes are impacted: RC2, RC4,
    RC5, CCM, GCM and OCB. For the CCM, GCM and OCB cipher modes, truncation of the IV can result in loss of
    confidentiality. For example, when following NIST's SP 800-38D section 8.2.1 guidance for constructing a
    deterministic IV for AES in GCM mode, truncation of the counter portion could lead to IV reuse. Both
    truncations and overruns of the key and overruns of the IV will produce incorrect results and could, in
    some cases, trigger a memory exception. However, these issues are not currently assessed as security
    critical. Changing the key and/or IV lengths is not considered to be a common operation and the vulnerable
    API was recently introduced. Furthermore it is likely that application developers will have spotted this
    problem during testing since decryption would fail unless both peers in the communication were similarly
    vulnerable. For these reasons we expect the probability of an application being vulnerable to this to be
    quite low. However if an application is vulnerable then this issue is considered very serious. For these
    reasons we have assessed this issue as Moderate severity overall. The OpenSSL SSL/TLS implementation is
    not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this because the
    issue lies outside of the FIPS provider boundary. OpenSSL 3.1 and 3.0 are vulnerable to this issue.
    (CVE-2023-5363)

  - Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or
    parameters may be very slow. Impact summary: Applications that use the functions DH_generate_key() to
    generate an X9.42 DH key may experience long delays. Likewise, applications that use DH_check_pub_key(),
    DH_check_pub_key_ex() or EVP_PKEY_public_check() to check an X9.42 DH key or X9.42 DH parameters may
    experience long delays. Where the key or parameters that are being checked have been obtained from an
    untrusted source this may lead to a Denial of Service. While DH_check() performs all the necessary checks
    (as of CVE-2023-3817), DH_check_pub_key() doesn't make any of these checks, and is therefore vulnerable
    for excessively large P and Q parameters. Likewise, while DH_generate_key() performs a check for an
    excessively large P, it doesn't check for an excessively large Q. An application that calls
    DH_generate_key() or DH_check_pub_key() and supplies a key or parameters obtained from an untrusted source
    could be vulnerable to a Denial of Service attack. DH_generate_key() and DH_check_pub_key() are also
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_pub_key_ex(),
    EVP_PKEY_public_check(), and EVP_PKEY_generate(). Also vulnerable are the OpenSSL pkey command line
    application when using the -pubcheck option, as well as the OpenSSL genpkey command line application.
    The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers
    are not affected by this issue. (CVE-2023-5678)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=40640");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream openssl package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'openssl-3.0.7-25.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-devel-3.0.7-25.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-libs-3.0.7-25.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'openssl-perl-3.0.7-25.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / openssl-perl');
}
