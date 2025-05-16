#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2024-2502.
##

include('compat.inc');

if (description)
{
  script_id(192206);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id(
    "CVE-2020-1971",
    "CVE-2021-3449",
    "CVE-2021-3450",
    "CVE-2021-3712",
    "CVE-2021-23840",
    "CVE-2021-23841",
    "CVE-2022-0778",
    "CVE-2022-1292",
    "CVE-2022-2068",
    "CVE-2022-2097",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2023-0215",
    "CVE-2023-0286",
    "CVE-2023-0464",
    "CVE-2023-0465",
    "CVE-2023-0466",
    "CVE-2023-2650",
    "CVE-2023-3446",
    "CVE-2023-3817",
    "CVE-2023-5678",
    "CVE-2024-0727"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux 2 : edk2 (ALAS-2024-2502)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It is, therefore, affected by multiple vulnerabilities as referenced in the ALAS2-2024-2502 advisory.

    A null pointer dereference flaw was found in openssl. A remote attacker, able to control the arguments of
    the GENERAL_NAME_cmp function, could cause the application, compiled with openssl to crash resulting in a
    denial of service. The highest threat from this vulnerability is to system availability. (CVE-2020-1971)

    Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissible length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    (CVE-2021-23840)

    The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. (CVE-2021-23841)

    A flaw was found in openssl. A server crash and denial of service attack could occur if a client sends a
    TLSv1.2 renegotiation ClientHello and omits the signature_algorithms extension but includes a
    signature_algorithms_cert extension. The highest threat from this vulnerability is to system availability.
    (CVE-2021-3449)

    A flaw was found in openssl. The flag that enables additional security checks of certificates present in a
    certificate chain was not enabled allowing a confirmation step to verify that certificates in the chain
    are valid CA certificates is bypassed. The highest threat from this vulnerability is to data
    confidentiality and integrity. (CVE-2021-3450)

    It was found that openssl assumed ASN.1 strings to be NUL terminated. A malicious actor may be able to
    force an application into calling openssl function with a specially crafted, non-NUL terminated string to
    deliberately hit this bug, which may result in a crash of the application, causing a Denial of Service
    attack, or possibly, memory disclosure. The highest threat from this vulnerability is to data
    confidentiality and system availability. (CVE-2021-3712)

    The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778) (CVE-2022-0778)

    The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This
    script is distributed by some operating systems in a manner where it is automatically executed. On such
    operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of
    the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool.
    Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n).
    Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd). (CVE-2022-1292)

    A flaw was found in OpenSSL. The issue in CVE-2022-1292 did not find other places in the `c_rehash` script
    where it possibly passed the file names of certificates being hashed to a command executed through the
    shell. Some operating systems distribute this script in a manner where it is automatically executed. On
    these operating systems, this flaw allows an attacker to execute arbitrary commands with the privileges of
    the script. (CVE-2022-2068)

    AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt
    the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was
    preexisting in the memory that wasn't written. In the special case of in place encryption, sixteen bytes
    of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and
    DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q
    (Affected 1.1.1-1.1.1p). (CVE-2022-2097)

    A timing-based side channel exists in the OpenSSL RSA Decryption implementation, which could be sufficient
    to recover a ciphertext across a network in a Bleichenbacher style attack. To achieve a successful
    decryption, an attacker would have to be able to send a very large number of trial messages for
    decryption. This issue affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP, and RSASVE. (CVE-2022-4304)

    The function PEM_read_bio_ex() reads a PEM file from a BIO and parses anddecodes the name (e.g.
    CERTIFICATE), any header data and the payload data.If the function succeeds then the name_out,
    header and data arguments arepopulated with pointers to buffers containing the relevant decoded data.
    Thecaller is responsible for freeing those buffers. It is possible to construct aPEM file that results in
    0 bytes of payload data. In this case PEM_read_bio_ex()will return a failure code but will populate the
    header argument with a pointerto a buffer that has already been freed. If the caller also frees this
    bufferthen a double free will occur. This will most likely lead to a crash. Thiscould be exploited by an
    attacker who has the ability to supply malicious PEMfiles for parsing to achieve a denial of service
    attack.

    The functions PEM_read_bio() and PEM_read() are simple wrappers aroundPEM_read_bio_ex() and therefore
    these functions are also directly affected.

    These functions are also called indirectly by a number of other OpenSSLfunctions including
    PEM_X509_INFO_read_bio_ex() andSSL_CTX_use_serverinfo_file() which are also vulnerable. Some OpenSSL
    internaluses of these functions are not vulnerable because the caller does not free theheader argument if
    PEM_read_bio_ex() returns a failure code. These locationsinclude the PEM_read_bio_TYPE() functions as well
    as the decoders introduced inOpenSSL 3.0.

    The OpenSSL asn1parse command line application is also impacted by this issue. (CVE-2022-4450)

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

    Issue summary: Checking excessively long DH keys or parameters may be very slow.

    Impact summary: Applications that use the functions DH_check(), DH_check_ex()or EVP_PKEY_param_check() to
    check a DH key or DH parameters may experience longdelays. Where the key or parameters that are being
    checked have been obtainedfrom an untrusted source this may lead to a Denial of Service.

    The function DH_check() performs various checks on DH parameters. One of thosechecks confirms that the
    modulus ('p' parameter) is not too large. Trying to usea very large modulus is slow and OpenSSL will not
    normally use a modulus whichis over 10,000 bits in length.

    However the DH_check() function checks numerous aspects of the key or parametersthat have been supplied.
    Some of those checks use the supplied modulus valueeven if it has already been found to be too large.

    An application that calls DH_check() and supplies a key or parameters obtainedfrom an untrusted source
    could be vulernable to a Denial of Service attack.

    The function DH_check() is itself called by a number of other OpenSSL functions.An application calling any
    of those other functions may similarly be affected.The other functions affected by this are DH_check_ex()
    andEVP_PKEY_param_check().

    Also vulnerable are the OpenSSL dhparam and pkeyparam command line applicationswhen using the '-check'
    option.

    The OpenSSL SSL/TLS implementation is not affected by this issue.The OpenSSL 3.0 and 3.1 FIPS providers
    are not affected by this issue. (CVE-2023-3446)

    Issue summary: Checking excessively long DH keys or parameters may be very slow.

    Impact summary: Applications that use the functions DH_check(), DH_check_ex()or EVP_PKEY_param_check() to
    check a DH key or DH parameters may experience longdelays. Where the key or parameters that are being
    checked have been obtainedfrom an untrusted source this may lead to a Denial of Service.

    The function DH_check() performs various checks on DH parameters. After fixingCVE-2023-3446 it was
    discovered that a large q parameter value can also triggeran overly long computation during some of these
    checks. A correct q value,if present, cannot be larger than the modulus p parameter, thus it isunnecessary
    to perform these checks if q is larger than p.

    An application that calls DH_check() and supplies a key or parameters obtainedfrom an untrusted source
    could be vulnerable to a Denial of Service attack.

    The function DH_check() is itself called by a number of other OpenSSL functions.An application calling any
    of those other functions may similarly be affected.The other functions affected by this are DH_check_ex()
    andEVP_PKEY_param_check().

    Also vulnerable are the OpenSSL dhparam and pkeyparam command line applicationswhen using the -check
    option.

    The OpenSSL SSL/TLS implementation is not affected by this issue.

    The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue. (CVE-2023-3817)

    Issue summary: Generating excessively long X9.42 DH keys or checkingexcessively long X9.42 DH keys or
    parameters may be very slow.

    Impact summary: Applications that use the functions DH_generate_key() togenerate an X9.42 DH key may
    experience long delays.  Likewise, applicationsthat use DH_check_pub_key(), DH_check_pub_key_ex() or
    EVP_PKEY_public_check()to check an X9.42 DH key or X9.42 DH parameters may experience long delays.Where
    the key or parameters that are being checked have been obtained froman untrusted source this may lead to a
    Denial of Service.

    While DH_check() performs all the necessary checks (as of CVE-2023-3817),DH_check_pub_key() doesn't make
    any of these checks, and is thereforevulnerable for excessively large P and Q parameters.

    Likewise, while DH_generate_key() performs a check for an excessively largeP, it doesn't check for an
    excessively large Q.

    An application that calls DH_generate_key() or DH_check_pub_key() andsupplies a key or parameters obtained
    from an untrusted source could bevulnerable to a Denial of Service attack.

    DH_generate_key() and DH_check_pub_key() are also called by a number ofother OpenSSL functions.  An
    application calling any of those otherfunctions may similarly be affected.  The other functions affected
    by thisare DH_check_pub_key_ex(), EVP_PKEY_public_check(), and EVP_PKEY_generate().

    Also vulnerable are the OpenSSL pkey command line application when using the-pubcheck option, as well as
    the OpenSSL genpkey command line application.

    The OpenSSL SSL/TLS implementation is not affected by this issue.

    The OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue. (CVE-2023-5678)

    Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of
    Service attack

    The package openssl098e is provided purely for binary compatibility with older Amazon Linux versions. It
    does not receive security updates. (CVE-2024-0727)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2024-2502.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2020-1971.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23840.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-23841.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3449.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3450.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2021-3712.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-0778.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-1292.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2068.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-2097.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4304.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-4450.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0215.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0286.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0465.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-0466.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-2650.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-3446.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-3817.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2023-5678.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-0727.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update edk2' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-3446");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:edk2-tools-python");
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
    {'reference':'edk2-aarch64-20200801stable-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-debuginfo-20200801stable-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-debuginfo-20200801stable-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-ovmf-20200801stable-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20200801stable-1.amzn2.0.5', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-20200801stable-1.amzn2.0.5', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-doc-20200801stable-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'edk2-tools-python-20200801stable-1.amzn2.0.5', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE}
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
