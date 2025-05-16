##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146591);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-23839", "CVE-2021-23840", "CVE-2021-23841");
  script_xref(name:"IAVA", value:"2021-A-0103-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2y Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2y. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2y advisory.

  - The OpenSSL public API function X509_issuer_and_serial_hash() attempts to create a unique hash value based
    on the issuer and serial number data contained within an X509 certificate. However it fails to correctly
    handle any errors that may occur while parsing the issuer field (which might occur if the issuer field is
    maliciously constructed). This may subsequently result in a NULL pointer deref and a crash leading to a
    potential denial of service attack. The function X509_issuer_and_serial_hash() is never directly called by
    OpenSSL itself so applications are only vulnerable if they use this function directly and they use it on
    certificates that may have been obtained from untrusted sources. OpenSSL versions 1.1.1i and below are
    affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1j. OpenSSL versions 1.0.2x
    and below are affected by this issue. However OpenSSL 1.0.2 is out of support and no longer receiving
    public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should
    upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i). Fixed in OpenSSL 1.0.2y (Affected
    1.0.2-1.0.2x). (CVE-2021-23841)

  - Calls to EVP_CipherUpdate, EVP_EncryptUpdate and EVP_DecryptUpdate may overflow the output length argument
    in some cases where the input length is close to the maximum permissable length for an integer on the
    platform. In such cases the return value from the function call will be 1 (indicating success), but the
    output length value will be negative. This could cause applications to behave incorrectly or crash.
    OpenSSL versions 1.1.1i and below are affected by this issue. Users of these versions should upgrade to
    OpenSSL 1.1.1j. OpenSSL versions 1.0.2x and below are affected by this issue. However OpenSSL 1.0.2 is out
    of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should
    upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.1.1j (Affected 1.1.1-1.1.1i).
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2-1.0.2x). (CVE-2021-23840)

  - OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to
    support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack
    when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed
    to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject
    connection attempts from a client where this special form of padding is present, because this indicates
    that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this
    is the version that is being requested). The implementation of this padding check inverted the logic so
    that the connection attempt is accepted if the padding is present, and rejected if it is absent. This
    means that such as server will accept a connection if a version rollback attack has occurred. Further the
    server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL
    1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2
    server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured
    SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in
    the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to
    this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This
    also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not
    support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding
    mode. Applications that directly call that function or use that padding mode will encounter this issue.
    However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a
    security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates.
    Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j.
    Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x). (CVE-2021-23839)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=30919ab80a478f2d81f2e9acdcca3fa4740cd547
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d58067e");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8252ee4d90f3f2004d3d0aeeed003ad49c9a7807
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95cac758");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=9b1129239f3ebb1d1c98ce9ed41d5c9476c47cb2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f389e444");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2021-23839");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2021-23840");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2021-23841");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20210216.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2y or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2y' },
  { 'min_version' : '1.0.2s', 'fixed_version' : '1.0.2y' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
