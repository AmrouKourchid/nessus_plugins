#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93814);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
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

  script_name(english:"OpenSSL 1.0.1 < 1.0.1u Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.1u. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.1u advisory.

  - Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a
    allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request
    extensions. (CVE-2016-6304)

  - The certificate parser in OpenSSL before 1.0.1u and 1.0.2 before 1.0.2i might allow remote attackers to
    cause a denial of service (out-of-bounds read) via crafted certificate operations, related to s3_clnt.c
    and s3_srvr.c. (CVE-2016-6306)

  - Integer overflow in the MDC2_Update function in crypto/mdc2/mdc2dgst.c in OpenSSL before 1.1.0 allows
    remote attackers to cause a denial of service (out-of-bounds write and application crash) or possibly have
    unspecified other impact via unknown vectors. (CVE-2016-6303)

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
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=00a4c1421407b6ac796688871b0a49a179c694d9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0049293a");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2c0d295e26306e15a92eb23a84a1802005c1c137
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?071796a4");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2b4029e68fd7002d2307e6c3cde0f3784eef9c83
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c010986");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=b77ab018b79a00f789b0fb85596b446b08be4c9d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a025cd5");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1bbe48ab149893a78bf99c8eb8895c928900a16f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9cbf336");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=bb1a4866034255749ac578adb06a76335fc117b1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4e68db1");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2177");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2178");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2179");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2180");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2181");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-2182");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6302");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6303");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6304");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1u or later.");
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
  { 'min_version' : '1.0.1', 'fixed_version' : '1.0.1u' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
