#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93815);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6306"
  );
  script_bugtraq_id(
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92982,
    92984,
    92987,
    93150,
    93153
  );

  script_name(english:"OpenSSL 1.0.2 < 1.0.2i Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2i. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2i advisory.

  - Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a
    allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request
    extensions. (CVE-2016-6304)

  - The certificate parser in OpenSSL before 1.0.1u and 1.0.2 before 1.0.2i might allow remote attackers to
    cause a denial of service (out-of-bounds read) via crafted certificate operations, related to s3_clnt.c
    and s3_srvr.c. (CVE-2016-6306)

  - Integer overflow in the MDC2_Update function in crypto/mdc2/mdc2dgst.c in OpenSSL before 1.1.0 allows
    remote attackers to cause a denial of service (out-of-bounds write and application crash) or possibly have
    unspecified other impact via unknown vectors. (CVE-2016-6303)

  - The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and
    products, have a birthday bound of approximately four billion blocks, which makes it easier for remote
    attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, as
    demonstrated by an HTTPS session using Triple DES in CBC mode, aka a Sweet32 attack. (CVE-2016-2183)

  - The tls_decrypt_ticket function in ssl/t1_lib.c in OpenSSL before 1.1.0 does not consider the HMAC size
    during validation of the ticket length, which allows remote attackers to cause a denial of service via a
    ticket that is too short. (CVE-2016-6302)

  - The DTLS implementation in OpenSSL before 1.1.0 does not properly restrict the lifetime of queue entries
    associated with unused out-of-order messages, which allows remote attackers to cause a denial of service
    (memory consumption) by maintaining many crafted DTLS sessions simultaneously, related to d1_lib.c,
    statem_dtls.c, statem_lib.c, and statem_srvr.c. (CVE-2016-2179)

  - The Anti-Replay feature in the DTLS implementation in OpenSSL before 1.1.0 mishandles early use of a new
    epoch number in conjunction with a large sequence number, which allows remote attackers to cause a denial
    of service (false-positive packet drops) via spoofed DTLS records, related to rec_layer_d1.c and
    ssl3_record.c. (CVE-2016-2181)

  - The BN_bn2dec function in crypto/bn/bn_print.c in OpenSSL before 1.1.0 does not properly validate division
    results, which allows remote attackers to cause a denial of service (out-of-bounds write and application
    crash) or possibly have unspecified other impact via unknown vectors. (CVE-2016-2182)

  - The TS_OBJ_print_bio function in crypto/ts/ts_lib.c in the X.509 Public Key Infrastructure Time-Stamp
    Protocol (TSP) implementation in OpenSSL through 1.0.2h allows remote attackers to cause a denial of
    service (out-of-bounds read and application crash) via a crafted time-stamp file that is mishandled by the
    openssl ts command. (CVE-2016-2180)

  - The dsa_sign_setup function in crypto/dsa/dsa_ossl.c in OpenSSL through 1.0.2h does not properly ensure
    the use of constant-time operations, which makes it easier for local users to discover a DSA private key
    via a timing side-channel attack. (CVE-2016-2178)

  - OpenSSL through 1.0.2h incorrectly uses pointer arithmetic for heap-buffer boundary checks, which might
    allow remote attackers to cause a denial of service (integer overflow and application crash) or possibly
    have unspecified other impact by leveraging unexpected malloc behavior, related to s3_srvr.c, ssl_sess.c,
    and t1_lib.c. (CVE-2016-2177)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=3884b47b7c255c2e94d9b387ee83c7e8bb981258
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0845121f");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=006a788c84e541c8920dd2ad85fb62b52185c519
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6643facb");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=26f2c5774f117aea588e8f31fad38bcf14e83bec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e507532");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1027ad4f34c30b8585592764b9a670ba36888269
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83da3354");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=baaabfd8fdcec04a691695fad9a664bea43202b6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1537458");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ea39b16b71e4e72a228a4535bd6d6a02c5edbc1f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7640eb6");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2177");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2178");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2179");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2180");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2181");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2182");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2183");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6302");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6303");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6304");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6306");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2i or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6303");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2i' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
