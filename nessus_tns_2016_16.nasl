#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97192);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

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
    "CVE-2016-6305",
    "CVE-2016-6306",
    "CVE-2016-6307",
    "CVE-2016-6308",
    "CVE-2016-6309",
    "CVE-2016-7052",
    "CVE-2016-9260"
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
    93149,
    93150,
    93151,
    93152,
    93153,
    93171,
    93177,
    95772
  );

  script_name(english:"Tenable Nessus 6.x < 6.9 Multiple Vulnerabilities (TNS-2016-16) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Tenable Nessus
application running on the remote host is 6.x prior to 6.9. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple integer overflow conditions exist in the
    OpenSSL component in s3_srvr.c, ssl_sess.c, and t1_lib.c
    due to improper use of pointer arithmetic for
    heap-buffer boundary checks. An unauthenticated, remote
    attacker can exploit this to cause a denial of service.
    (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    OpenSSL component in the dsa_sign_setup() function in
    dsa_ossl.c due to a failure to properly ensure the use
    of constant-time operations. An unauthenticated, remote
    attacker can exploit this, via a timing side-channel
    attack, to disclose DSA key information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the OpenSSL
    component in the DTLS implementation due to a failure to
    properly restrict the lifetime of queue entries
    associated with unused out-of-order messages. An
    unauthenticated, remote attacker can exploit this, by
    maintaining multiple crafted DTLS sessions
    simultaneously, to exhaust memory. (CVE-2016-2179)

  - An out-of-bounds read error exists in the OpenSSL
    component in the X.509 Public Key Infrastructure
    Time-Stamp Protocol (TSP) implementation. An
    unauthenticated, remote attacker can exploit this, via a
    crafted time-stamp file that is mishandled by the
    'openssl ts' command, to cause denial of service or to
    disclose sensitive information. (CVE-2016-2180)

  - A denial of service vulnerability exists in the OpenSSL
    component in the Anti-Replay feature in the DTLS
    implementation due to improper handling of epoch
    sequence numbers in records. An unauthenticated, remote
    attacker can exploit this, via spoofed DTLS records, to
    cause legitimate packets to be dropped. (CVE-2016-2181)

  - An overflow condition exists in the OpenSSL component in
    the BN_bn2dec() function in bn_print.c due to improper
    validation of user-supplied input when handling BIGNUM
    values. An unauthenticated, remote attacker can exploit
    this to crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the OpenSSL
    component in the 3DES and Blowfish algorithms due to the
    use of weak 64-bit block ciphers by default. A
    man-in-the-middle attacker who has sufficient resources
    can exploit this vulnerability, via a 'birthday' attack,
    to detect a collision that leaks the XOR between the
    fixed secret and a known plaintext, allowing the
    disclosure of the secret text, such as secure HTTPS
    cookies, and possibly resulting in the hijacking of an
    authenticated session. (CVE-2016-2183)

  - A flaw exists in the OpenSSL component in the
    tls_decrypt_ticket() function in t1_lib.c due to
    improper handling of ticket HMAC digests.
    An unauthenticated, remote attacker can exploit this,
    via a ticket that is too short, to crash the process,
    resulting in a denial of service. (CVE-2016-6302)

  - An integer overflow condition exists in the OpenSSL
    component in the MDC2_Update() function in mdc2dgst.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in a
    denial of service condition or possibly the execution of
    arbitrary code. (CVE-2016-6303)

  - A flaw exists in the OpenSSL component in the
    ssl_parse_clienthello_tlsext() function in t1_lib.c due
    to improper handling of overly large OCSP Status Request
    extensions from clients. An unauthenticated, remote
    attacker can exploit this, via large OCSP Status Request
    extensions, to exhaust memory resources, resulting in a
    denial of service condition. (CVE-2016-6304)

  - A flaw exists in the OpenSSL component in the SSL_peek()
    function in rec_layer_s3.c due to improper handling of
    empty records. An unauthenticated, remote attacker can
    exploit this, by triggering a zero-length record in an
    SSL_peek call, to cause an infinite loop, resulting in a
    denial of service condition. (CVE-2016-6305)

  - An out-of-bounds read error exists in the OpenSSL
    component in the certificate parser that allows an
    unauthenticated, remote attacker to cause a denial of
    service via crafted certificate operations.
    (CVE-2016-6306)

  - A denial of service vulnerability exists in the OpenSSL
    component in the state-machine implementation due to a
    failure to check for an excessive length before
    allocating memory. An unauthenticated, remote attacker
    can exploit this, via a crafted TLS message, to exhaust
    memory resources. (CVE-2016-6307)

  - A denial of service vulnerability exists in the OpenSSL
    component in the DTLS implementation due to improper
    handling of excessively long DTLS messages. An
    unauthenticated, remote attacker can exploit this, via a
    crafted DTLS message, to exhaust available memory
    resources. (CVE-2016-6308)

  - A remote code execution vulnerability exists in the
    OpenSSL component in the read_state_machine() function
    in statem.c due to improper handling of messages larger
    than 16k. An  unauthenticated, remote attacker can
    exploit this, via a specially crafted message, to cause
    a use-after-free error, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6309)

  - A denial of service vulnerability exists in the OpenSSL
    component in x509_vfy.c due to improper handling of
    certificate revocation lists (CRLs). An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted CRL, to cause a NULL pointer dereference,
    resulting in a crash of the service. (CVE-2016-7052)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-9260)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-16");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160926.txt");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus version 6.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6309");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

	script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
	script_require_keys("installed_sw/Tenable Nessus");
  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.9.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);