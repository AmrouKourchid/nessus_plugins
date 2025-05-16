#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202402-08.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(189977);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/04");

  script_cve_id(
    "CVE-2022-3358",
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0286",
    "CVE-2023-0401",
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-2650",
    "CVE-2023-2975",
    "CVE-2023-3446",
    "CVE-2023-3817"
  );

  script_name(english:"GLSA-202402-08 : OpenSSL: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202402-08 (OpenSSL: Multiple Vulnerabilities)

  - OpenSSL supports creating a custom cipher via the legacy EVP_CIPHER_meth_new() function and associated
    function calls. This function was deprecated in OpenSSL 3.0 and application authors are instead encouraged
    to use the new provider mechanism in order to implement custom ciphers. OpenSSL versions 3.0.0 to 3.0.5
    incorrectly handle legacy custom ciphers passed to the EVP_EncryptInit_ex2(), EVP_DecryptInit_ex2() and
    EVP_CipherInit_ex2() functions (as well as other similarly named encryption and decryption initialisation
    functions). Instead of using the custom cipher directly it incorrectly tries to fetch an equivalent cipher
    from the available providers. An equivalent cipher is found based on the NID passed to
    EVP_CIPHER_meth_new(). This NID is supposed to represent the unique NID for a given cipher. However it is
    possible for an application to incorrectly pass NID_undef as this value in the call to
    EVP_CIPHER_meth_new(). When NID_undef is used in this way the OpenSSL encryption/decryption initialisation
    function will match the NULL cipher as being equivalent and will fetch this from the available providers.
    This will succeed if the default provider has been loaded (or if a third party provider has been loaded
    that offers this cipher). Using the NULL cipher means that the plaintext is emitted as the ciphertext.
    Applications are only affected by this issue if they call EVP_CIPHER_meth_new() using NID_undef and
    subsequently use it in a call to an encryption/decryption initialisation function. Applications that only
    use SSL/TLS are not impacted by this issue. Fixed in OpenSSL 3.0.6 (Affected 3.0.0-3.0.5). (CVE-2022-3358)

  - A read buffer overrun can be triggered in X.509 certificate verification, specifically in name constraint
    checking. Note that this occurs after certificate chain signature verification and requires either a CA to
    have signed the malicious certificate or for the application to continue certificate verification despite
    failure to construct a path to a trusted issuer. The read buffer overrun might result in a crash which
    could lead to a denial of service attack. In theory it could also result in the disclosure of private
    memory contents (such as private keys, or sensitive plaintext) although we are not aware of any working
    exploit leading to memory contents disclosure as of the time of release of this advisory. In a TLS client,
    this can be triggered by connecting to a malicious server. In a TLS server, this can be triggered if the
    server requests client authentication and a malicious client connects. (CVE-2022-4203)

  - A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient
    to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption an attacker would have to be able to send a very large number of trial messages for decryption.
    The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS
    connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An
    attacker that had observed a genuine connection between a client and a server could use this flaw to send
    trial messages to the server and record the time taken to process them. After a sufficiently large number
    of messages the attacker could recover the pre-master secret used for the original connection and thus be
    able to decrypt the application data sent over that connection. (CVE-2022-4304)

  - The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and decodes the name (e.g.
    CERTIFICATE), any header data and the payload data. If the function succeeds then the name_out,
    header and data arguments are populated with pointers to buffers containing the relevant decoded data.
    The caller is responsible for freeing those buffers. It is possible to construct a PEM file that results
    in 0 bytes of payload data. In this case PEM_read_bio_ex() will return a failure code but will populate
    the header argument with a pointer to a buffer that has already been freed. If the caller also frees this
    buffer then a double free will occur. This will most likely lead to a crash. This could be exploited by an
    attacker who has the ability to supply malicious PEM files for parsing to achieve a denial of service
    attack. The functions PEM_read_bio() and PEM_read() are simple wrappers around PEM_read_bio_ex() and
    therefore these functions are also directly affected. These functions are also called indirectly by a
    number of other OpenSSL functions including PEM_X509_INFO_read_bio_ex() and SSL_CTX_use_serverinfo_file()
    which are also vulnerable. Some OpenSSL internal uses of these functions are not vulnerable because the
    caller does not free the header argument if PEM_read_bio_ex() returns a failure code. These locations
    include the PEM_read_bio_TYPE() functions as well as the decoders introduced in OpenSSL 3.0. The OpenSSL
    asn1parse command line application is also impacted by this issue. (CVE-2022-4450)

  - The public API function BIO_new_NDEF is a helper function used for streaming ASN.1 data via a BIO. It is
    primarily used internally to OpenSSL to support the SMIME, CMS and PKCS7 streaming capabilities, but may
    also be called directly by end user applications. The function receives a BIO from the caller, prepends a
    new BIO_f_asn1 filter BIO onto the front of it to form a BIO chain, and then returns the new head of the
    BIO chain to the caller. Under certain conditions, for example if a CMS recipient public key is invalid,
    the new filter BIO is freed and the function returns a NULL result indicating a failure. However, in this
    case, the BIO chain is not properly cleaned up and the BIO passed by the caller still retains internal
    pointers to the previously freed filter BIO. If the caller then goes on to call BIO_pop() on the BIO then
    a use-after-free will occur. This will most likely result in a crash. This scenario occurs directly in the
    internal function B64_write_ASN1() which may cause BIO_new_NDEF() to be called and will subsequently call
    BIO_pop() on the BIO. This internal function is in turn called by the public API functions
    PEM_write_bio_ASN1_stream, PEM_write_bio_CMS_stream, PEM_write_bio_PKCS7_stream, SMIME_write_ASN1,
    SMIME_write_CMS and SMIME_write_PKCS7. Other public API functions that may be impacted by this include
    i2d_ASN1_bio_stream, BIO_new_CMS, BIO_new_PKCS7, i2d_CMS_bio_stream and i2d_PKCS7_bio_stream. The OpenSSL
    cms and smime command line applications are similarly affected. (CVE-2023-0215)

  - An invalid pointer dereference on read can be triggered when an application tries to load malformed PKCS7
    data with the d2i_PKCS7(), d2i_PKCS7_bio() or d2i_PKCS7_fp() functions. The result of the dereference is
    an application crash which could lead to a denial of service attack. The TLS implementation in OpenSSL
    does not call this function however third party applications might call these functions on untrusted data.
    (CVE-2023-0216)

  - An invalid pointer dereference on read can be triggered when an application tries to check a malformed DSA
    public key by the EVP_PKEY_public_check() function. This will most likely lead to an application crash.
    This function can be called on public keys supplied from untrusted sources which could allow an attacker
    to cause a denial of service attack. The TLS implementation in OpenSSL does not call this function but
    applications might call the function if there are additional security requirements imposed by standards
    such as FIPS 140-3. (CVE-2023-0217)

  - There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.
    X.400 addresses were parsed as an ASN1_STRING but the public structure definition for GENERAL_NAME
    incorrectly specified the type of the x400Address field as ASN1_TYPE. This field is subsequently
    interpreted by the OpenSSL function GENERAL_NAME_cmp as an ASN1_TYPE rather than an ASN1_STRING. When CRL
    checking is enabled (i.e. the application sets the X509_V_FLAG_CRL_CHECK flag), this vulnerability may
    allow an attacker to pass arbitrary pointers to a memcmp call, enabling them to read memory contents or
    enact a denial of service. In most cases, the attack requires the attacker to provide both the certificate
    chain and CRL, neither of which need to have a valid signature. If the attacker only controls one of these
    inputs, the other input must already contain an X.400 address as a CRL distribution point, which is
    uncommon. As such, this vulnerability is most likely to only affect applications which have implemented
    their own functionality for retrieving CRLs over a network. (CVE-2023-0286)

  - A NULL pointer can be dereferenced when signatures are being verified on PKCS7 signed or
    signedAndEnveloped data. In case the hash algorithm used for the signature is known to the OpenSSL library
    but the implementation of the hash algorithm is not available the digest initialization will fail. There
    is a missing check for the return value from the initialization function which later leads to invalid
    usage of the digest API most likely leading to a crash. The unavailability of an algorithm can be caused
    by using FIPS enabled configuration of providers or more commonly by not loading the legacy provider.
    PKCS7 data is processed by the SMIME library calls and also by the time stamp (TS) library calls. The TLS
    implementation in OpenSSL does not call these functions however third party applications would be affected
    if they call these functions to verify signatures on untrusted data. (CVE-2023-0401)

  - A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

  - Applications that use a non-default option when verifying certificates may be vulnerable to an attack from
    a malicious CA to circumvent certain checks. Invalid certificate policies in leaf certificates are
    silently ignored by OpenSSL and other certificate policy checks are skipped for that certificate. A
    malicious CA could use this to deliberately assert invalid certificate policies in order to circumvent
    policy checking on the certificate altogether. Policy processing is disabled by default but can be enabled
    by passing the `-policy' argument to the command line utilities or by calling the
    `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0465)

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

  - Issue summary: Processing some specially crafted ASN.1 object identifiers or data containing them may be
    very slow. Impact summary: Applications that use OBJ_obj2txt() directly, or use any of the OpenSSL
    subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS with no message size limit may experience notable to
    very long delays when processing those messages, which may lead to a Denial of Service. An OBJECT
    IDENTIFIER is composed of a series of numbers - sub-identifiers - most of which have no size limit.
    OBJ_obj2txt() may be used to translate an ASN.1 OBJECT IDENTIFIER given in DER encoding form (using the
    OpenSSL type ASN1_OBJECT) to its canonical numeric text form, which are the sub-identifiers of the OBJECT
    IDENTIFIER in decimal form, separated by periods. When one of the sub-identifiers in the OBJECT IDENTIFIER
    is very large (these are sizes that are seen as absurdly large, taking up tens or hundreds of KiBs), the
    translation to a decimal number in text may take a very long time. The time complexity is O(n^2) with 'n'
    being the size of the sub-identifiers in bytes (*). With OpenSSL 3.0, support to fetch cryptographic
    algorithms using names / identifiers in string form was introduced. This includes using OBJECT IDENTIFIERs
    in canonical numeric text form as identifiers for fetching algorithms. Such OBJECT IDENTIFIERs may be
    received through the ASN.1 structure AlgorithmIdentifier, which is commonly used in multiple protocols to
    specify what cryptographic algorithm should be used to sign or verify, encrypt or decrypt, or digest
    passed data. Applications that call OBJ_obj2txt() directly with untrusted data are affected, with any
    version of OpenSSL. If the use is for the mere purpose of display, the severity is considered low. In
    OpenSSL 3.0 and newer, this affects the subsystems OCSP, PKCS7/SMIME, CMS, CMP/CRMF or TS. It also impacts
    anything that processes X.509 certificates, including simple things like verifying its signature. The
    impact on TLS is relatively low, because all versions of OpenSSL have a 100KiB limit on the peer's
    certificate chain. Additionally, this only impacts clients, or servers that have explicitly enabled client
    authentication. In OpenSSL 1.1.1 and 1.0.2, this only affects displaying diverse objects, such as X.509
    certificates. This is assumed to not happen in such a way that it would cause a Denial of Service, so
    these versions are considered not affected by this issue in such a way that it would be cause for concern,
    and the severity is therefore considered low. (CVE-2023-2650)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202402-08");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=876787");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=893446");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=902779");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903545");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=907413");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910556");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=911560");
  script_set_attribute(attribute:"solution", value:
"All OpenSSL users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=dev-libs/openssl-3.0.10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3358");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'dev-libs/openssl',
    'unaffected' : make_list("ge 3.0.10"),
    'vulnerable' : make_list("lt 3.0.10")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'OpenSSL');
}
