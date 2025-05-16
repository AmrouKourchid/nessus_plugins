#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201081);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2024-5535");

  script_name(english:"OpenSSL 3.2.0 < 3.2.3 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.2.3. It is, therefore, affected by a vulnerability as
referenced in the 3.2.3 advisory.

  - Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an empty supported client
    protocols buffer may cause a crash or memory contents to be sent to the peer. Impact summary: A buffer
    overread can have a range of potential consequences such as unexpected application beahviour or a crash.
    In particular this issue could result in up to 255 bytes of arbitrary private data from memory being sent
    to the peer leading to a loss of confidentiality. However, only applications that directly call the
    SSL_select_next_proto function with a 0 length list of supported client protocols are affected by this
    issue. This would normally never be a valid scenario and is typically not under attacker control but may
    occur by accident in the case of a configuration or programming error in the calling application. The
    OpenSSL API function SSL_select_next_proto is typically used by TLS applications that support ALPN
    (Application Layer Protocol Negotiation) or NPN (Next Protocol Negotiation). NPN is older, was never
    standardised and is deprecated in favour of ALPN. We believe that ALPN is significantly more widely
    deployed than NPN. The SSL_select_next_proto function accepts a list of protocols from the server and a
    list of protocols from the client and returns the first protocol that appears in the server list that also
    appears in the client list. In the case of no overlap between the two lists it returns the first item in
    the client list. In either case it will signal whether an overlap between the two lists was found. In the
    case where SSL_select_next_proto is called with a zero length client list it fails to notice this
    condition and returns the memory immediately following the client list pointer (and reports that there was
    no overlap in the lists). This function is typically called from a server side application callback for
    ALPN or a client side application callback for NPN. In the case of ALPN the list of protocols supplied by
    the client is guaranteed by libssl to never be zero in length. The list of server protocols comes from the
    application and should never normally be expected to be of zero length. In this case if the
    SSL_select_next_proto function has been called as expected (with the list supplied by the client passed in
    the client/client_len parameters), then the application will not be vulnerable to this issue. If the
    application has accidentally been configured with a zero length server list, and has accidentally passed
    that zero length server list in the client/client_len parameters, and has additionally failed to correctly
    handle a no overlap response (which would normally result in a handshake failure in ALPN) then it will
    be vulnerable to this problem. In the case of NPN, the protocol permits the client to opportunistically
    select a protocol when there is no overlap. OpenSSL returns the first client protocol in the no overlap
    case in support of this. The list of client protocols comes from the application and should never normally
    be expected to be of zero length. However if the SSL_select_next_proto function is accidentally called
    with a client_len of 0 then an invalid memory pointer will be returned instead. If the application uses
    this output as the opportunistic protocol then the loss of confidentiality will occur. This issue has been
    assessed as Low severity because applications are most likely to be vulnerable if they are using NPN
    instead of ALPN - but NPN is not widely used. It also requires an application configuration or programming
    error. Finally, this issue would not typically be under attacker control making active exploitation
    unlikely. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue. Due to the low
    severity of this issue we are not issuing new releases of OpenSSL at this time. The fix will be included
    in the next releases when they become available. Found by Joseph Birr-Pixton. Thanks to David Benjamin
    (Google). Fix developed by Matt Caswell. Fixed in OpenSSL 1.1.1za (premium support) (Affected since
    1.1.1). (CVE-2024-5535)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/99fb785a5f85315b95288921a321a935ea29a51e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3482f2f1");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-5535");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.2.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5535");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3.2.0', 'fixed_version' : '3.2.3' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
