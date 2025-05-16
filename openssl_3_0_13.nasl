#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185160);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2023-5678",
    "CVE-2023-6129",
    "CVE-2023-6237",
    "CVE-2024-0727"
  );
  script_xref(name:"IAVA", value:"2024-A-0121-S");

  script_name(english:"OpenSSL 3.0.0 < 3.0.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.0.13. It is, therefore, affected by multiple
vulnerabilities as referenced in the 3.0.13 advisory.

  - Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a
    potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from
    untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and
    may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL
    does not correctly check for this case. This can lead to a NULL pointer dereference that results in
    OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs
    then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are:
    PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and
    PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function
    is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and
    3.0 are not affected by this issue. (CVE-2024-0727)

  - Issue summary: Checking excessively long invalid RSA public keys may take a long time. Impact summary:
    Applications that use the function EVP_PKEY_public_check() to check RSA public keys may experience long
    delays. Where the key that is being checked has been obtained from an untrusted source this may lead to a
    Denial of Service. When function EVP_PKEY_public_check() is called on RSA public keys, a computation is
    done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more
    large primes and this computation completes quickly. However, if n is an overly large prime, then this
    computation would take a long time. An application that calls EVP_PKEY_public_check() and supplies an RSA
    key obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function
    EVP_PKEY_public_check() is not called from other OpenSSL functions however it is called from the OpenSSL
    pkey command line application. For that reason that application is also vulnerable if used with the
    '-pubin' and '-check' options on untrusted data. The OpenSSL SSL/TLS implementation is not affected by
    this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue. (CVE-2023-6237)

  - Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might
    corrupt the internal state of applications running on PowerPC CPU based platforms if the CPU provides
    vector instructions. Impact summary: If an attacker can influence whether the POLY1305 MAC algorithm is
    used, the application state might be corrupted with various application dependent consequences. The
    POLY1305 MAC (message authentication code) implementation in OpenSSL for PowerPC CPUs restores the
    contents of vector registers in a different order than they are saved. Thus the contents of some of these
    vector registers are corrupted when returning to the caller. The vulnerable code is used only on newer
    PowerPC processors supporting the PowerISA 2.07 instructions. The consequences of this kind of internal
    application state corruption can be various - from no consequences, if the calling application does not
    depend on the contents of non-volatile XMM registers at all, to the worst consequences, where the attacker
    could get complete control of the application process. However unless the compiler uses the vector
    registers for storing pointers, the most likely consequence, if any, would be an incorrect result of some
    application dependent calculations or a crash leading to a denial of service. The POLY1305 MAC algorithm
    is most frequently used as part of the CHACHA20-POLY1305 AEAD (authenticated encryption with associated
    data) algorithm. The most common usage of this AEAD cipher is with TLS protocol versions 1.2 and 1.3. If
    this cipher is enabled on the server a malicious client can influence whether this AEAD cipher is used.
    This implies that TLS server applications using OpenSSL can be potentially impacted. However we are
    currently not aware of any concrete application that would be affected by this issue therefore we consider
    this a Low severity security issue. (CVE-2023-6129)

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
  # https://github.com/openssl/openssl/commit/db925ae2e65d0d925adef429afc37f75bd1c2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02bfb3df");
  # https://github.com/openssl/openssl/commit/050d26383d4e264966fb83428e72d5d48f402d35
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71a978e4");
  # https://github.com/openssl/openssl/commit/18c02492138d1eb8b6548cb26e7b625fb2414a2a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccacbb1d");
  # https://github.com/openssl/openssl/commit/09df4395b5071217b76dc7d3d2e630eb8c5a79c2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc067b0a");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-5678");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-6129");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-6237");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-0727");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.0.13 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.13' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
