#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80567);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-8275",
    "CVE-2015-0204",
    "CVE-2015-0205",
    "CVE-2015-0206"
  );
  script_bugtraq_id(
    71934,
    71935,
    71936,
    71937,
    71939,
    71940,
    71941,
    71942
  );
  script_xref(name:"CERT", value:"243585");

  script_name(english:"OpenSSL 1.0.0 < 1.0.0p Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.0p. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.0p advisory.

  - Memory leak in the dtls1_buffer_record function in d1_pkt.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1
    before 1.0.1k allows remote attackers to cause a denial of service (memory consumption) by sending many
    duplicate records for the next epoch, leading to failure of replay detection. (CVE-2015-0206)

  - The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k
    accepts client authentication with a Diffie-Hellman (DH) certificate without requiring a CertificateVerify
    message, which allows remote attackers to obtain access without knowledge of a private key via crafted TLS
    Handshake Protocol traffic to a server that recognizes a Certification Authority with DH support.
    (CVE-2015-0205)

  - The BN_sqr implementation in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k does not
    properly calculate the square of a BIGNUM value, which might make it easier for remote attackers to defeat
    cryptographic protection mechanisms via unspecified vectors, related to crypto/bn/asm/mips.pl,
    crypto/bn/asm/x86_64-gcc.c, and crypto/bn/bn_asm.c. (CVE-2014-3570)

  - The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
    before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate
    brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the FREAK
    issue. NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated
    with servers or other TLS implementations. (CVE-2015-0204)

  - OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k does not enforce certain constraints
    on certificate data, which allows remote attackers to defeat a fingerprint-based certificate-blacklist
    protection mechanism by including crafted data within a certificate's unsigned portion, related to
    crypto/asn1/a_verify.c, crypto/dsa/dsa_asn1.c, crypto/ecdsa/ecs_vrf.c, and crypto/x509/x_all.c.
    (CVE-2014-8275)

  - The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
    before 1.0.1k allows remote SSL servers to conduct ECDHE-to-ECDH downgrade attacks and trigger a loss of
    forward secrecy by omitting the ServerKeyExchange message. (CVE-2014-3572)

  - OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote attackers to cause a
    denial of service (NULL pointer dereference and application crash) via a crafted DTLS message that is
    processed with a different read operation for the handshake header than for the handshake body, related to
    the dtls1_get_record function in d1_pkt.c and the ssl3_read_n function in s3_pkt.c. (CVE-2014-3571)

  - The ssl23_get_client_hello function in s23_srvr.c in OpenSSL 0.9.8zc, 1.0.0o, and 1.0.1j does not properly
    handle attempts to use unsupported protocols, which allows remote attackers to cause a denial of service
    (NULL pointer dereference and daemon crash) via an unexpected handshake, as demonstrated by an SSLv3
    handshake to a no-ssl3 application with certain error handling. NOTE: this issue became relevant after the
    CVE-2014-3568 fix. (CVE-2014-3569)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-3569");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-3570");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-3571");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-3572");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-8275");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2015-0204");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2015-0205");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2015-0206");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150108.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.0p or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0205");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.0', 'fixed_version' : '1.0.0p' },
  { 'min_version' : '1.0.0o', 'fixed_version' : '1.0.0p' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
