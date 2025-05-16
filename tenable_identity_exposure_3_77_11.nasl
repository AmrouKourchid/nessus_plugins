#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235471);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-9143", 
    "CVE-2024-12797", 
    "CVE-2024-13176", 
    "CVE-2025-32433"
  );

  script_name(english:"Tenable Identity Exposure < 3.77.11 Multiple Vulnerabilities (TNS-2025-07)");

  script_set_attribute(attribute:"synopsis", value:
"An identity security and threat detection platform running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Tenable Identity Exposure running on the remote host is prior to 3.77.11. It is, therefore, affected by
multiple vulnerabilities according to advisory TNS-2025-07, including the following:

  - Issue summary: Clients using RFC7250 Raw Public Keys (RPKs) to authenticate a server may fail to notice 
    that the server was not authenticated, because handshakes don't abort as expected when the 
    SSL_VERIFY_PEER verification mode is set. Impact summary: TLS and DTLS connections using raw public keys 
    may be vulnerable to man-in-middle attacks when server authentication failure is not detected by clients. 
    RPKs are disabled by default in both TLS clients and TLS servers. The issue only arises when TLS clients 
    explicitly enable RPK use by the server, and the server, likewise, enables sending of an RPK instead of 
    an X.509 certificate chain. The affected clients are those that then rely on the handshake to fail when 
    the server's RPK fails to match one of the expected public keys, by setting the verification mode to 
    SSL_VERIFY_PEER. Clients that enable server-side raw public keys can still find out that raw public key 
    verification failed by calling SSL_get_verify_result(), and those that do, and take appropriate action, 
    are not affected. This issue was introduced in the initial implementation of RPK support in OpenSSL 3.2. 
    The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are not affected by this issue. (CVE-2024-12797)

  - Issue summary: A timing side-channel which could potentially allow recovering the private key exists in 
    the ECDSA signature computation. Impact summary: A timing side-channel in ECDSA signature computations 
    could allow recovering the private key by an attacker. However, measuring the timing would require either 
    local access to the signing application or a very fast network connection with low latency. There is a 
    timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce value is zero. 
    This can happen with significant probability only for some of the supported elliptic curves. In 
    particular the NIST P-521 curve is affected. To be able to measure this leak, the attacker process must 
    either be located in the same physical computer or must have a very fast network connection with low 
    latency. For that reason the severity of this vulnerability is Low. The FIPS modules in 3.4, 3.3, 3.2, 
    3.1 and 3.0 are affected by this issue. (CVE-2024-13176)

  - Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, 
    OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote 
    code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain 
    unauthorized access to affected systems and execute arbitrary commands without valid credentials. This 
    issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround 
    involves disabling the SSH server or to prevent access via firewall rules. (CVE-2025-32433)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2025-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Identity Exposure version 3.77.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32433");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:tenable_ad");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:tenable:tenable_identity_exposure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ad_win_installed.nbin", "tenable_ad_web_detect.nbin");
  script_require_keys("installed_sw/Tenable.ad");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable.ad');

var constraints = [
  {'fixed_version': '3.77.11'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);