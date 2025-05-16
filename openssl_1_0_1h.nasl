#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(74364);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470",
    "CVE-2014-8176",
    "CVE-2015-0292"
  );
  script_bugtraq_id(
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    73228
  );
  script_xref(name:"CERT", value:"978508");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1h Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.1h. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.1h advisory.

  - The dtls1_clear_queues function in ssl/d1_lib.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h frees data structures without considering that application data can arrive between a
    ChangeCipherSpec message and a Finished message, which allows remote DTLS peers to cause a denial of
    service (memory corruption and application crash) or possibly have unspecified other impact via unexpected
    application data. (CVE-2014-8176)

  - Integer underflow in the EVP_DecodeUpdate function in crypto/evp/encode.c in the base64-decoding
    implementation in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h allows remote
    attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via
    crafted base64 data that triggers a buffer overflow. (CVE-2015-0292)

  - OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not properly restrict processing
    of ChangeCipherSpec messages, which allows man-in-the-middle attackers to trigger use of a zero-length
    master key in certain OpenSSL-to-OpenSSL communications, and consequently hijack sessions or obtain
    sensitive information, via a crafted TLS handshake, aka the CCS Injection vulnerability. (CVE-2014-0224)

  - The dtls1_get_message_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and
    1.0.1 before 1.0.1h allows remote attackers to cause a denial of service (recursion and client crash) via
    a DTLS hello message in an invalid DTLS handshake. (CVE-2014-0221)

  - The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and
    1.0.1 before 1.0.1h does not properly validate fragment lengths in DTLS ClientHello messages, which allows
    remote attackers to execute arbitrary code or cause a denial of service (buffer overflow and application
    crash) via a long non-initial fragment. (CVE-2014-0195)

  - The ssl3_send_client_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m,
    and 1.0.1 before 1.0.1h, when an anonymous ECDH cipher suite is used, allows remote attackers to cause a
    denial of service (NULL pointer dereference and client crash) by triggering a NULL certificate value.
    (CVE-2014-3470)

  - The do_ssl3_write function in s3_pkt.c in OpenSSL 1.x through 1.0.1g, when SSL_MODE_RELEASE_BUFFERS is
    enabled, does not properly manage a buffer pointer during certain recursive calls, which allows remote
    attackers to cause a denial of service (NULL pointer dereference and application crash) via vectors that
    trigger an alert condition. (CVE-2014-0198)

  - Race condition in the ssl3_read_bytes function in s3_pkt.c in OpenSSL through 1.0.1g, when
    SSL_MODE_RELEASE_BUFFERS is enabled, allows remote attackers to inject data across sessions or cause a
    denial of service (use-after-free and parsing error) via an SSL connection in a multithreaded environment.
    (CVE-2010-5298)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2010-5298");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-0195");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-0198");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-0221");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-0224");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-3470");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2014-8176");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2015-0292");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1h or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0292");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.1', 'fixed_version' : '1.0.1h' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
