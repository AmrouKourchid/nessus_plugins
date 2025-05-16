#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213289);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-4603",
    "CVE-2024-4741",
    "CVE-2024-5458",
    "CVE-2024-5535",
    "CVE-2024-5585",
    "CVE-2024-6119",
    "CVE-2024-8932",
    "CVE-2024-11233",
    "CVE-2024-11236"
  );

  script_name(english:"Tenable Security Center Multiple Vulnerabilities (TNS-2024-21)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Security Center installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is version 6.4.5. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2024-21 advisory.

  - In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14, uncontrolled long string
    inputs to ldap_escape() function on 32-bit systems can cause an integer overflow, resulting in an out-of-
    bounds write. (CVE-2024-11236)

  - In PHP versions 8.1.* before 8.1.31, 8.2.* before 8.2.26, 8.3.* before 8.3.14, due to an error in
    convert.quoted-printable-decode filter certain data can lead to buffer overread by one byte, which can in
    certain circumstances lead to crashes or disclose content of other memory areas. (CVE-2024-11233)

  - Issue summary: Checking excessively long DSA keys or parameters may be very slow. Impact summary:
    Applications that use the functions EVP_PKEY_param_check() or EVP_PKEY_public_check() to check a DSA
    public key or DSA parameters may experience long delays. Where the key or parameters that are being
    checked have been obtained from an untrusted source this may lead to a Denial of Service. The functions
    EVP_PKEY_param_check() or EVP_PKEY_public_check() perform various checks on DSA parameters. Some of those
    computations take a long time if the modulus (`p` parameter) is too large. Trying to use a very large
    modulus is slow and OpenSSL will not allow using public keys with a modulus which is over 10,000 bits in
    length for signature verification. However the key and parameter check functions do not limit the modulus
    size when performing the checks. An application that calls EVP_PKEY_param_check() or
    EVP_PKEY_public_check() and supplies a key or parameters obtained from an untrusted source could be
    vulnerable to a Denial of Service attack. These functions are not called by OpenSSL itself on untrusted
    DSA keys so only applications that directly call these functions may be vulnerable. Also vulnerable are
    the OpenSSL pkey and pkeyparam command line applications when using the `-check` option. The OpenSSL
    SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected
    by this issue. (CVE-2024-4603)

  - Issue summary: Calling the OpenSSL API function SSL_free_buffers may cause memory to be accessed that was
    previously freed in some situations Impact summary: A use after free can have a range of potential
    consequences such as the corruption of valid data, crashes or execution of arbitrary code. However, only
    applications that directly call the SSL_free_buffers function are affected by this issue. Applications
    that do not call this function are not vulnerable. Our investigations indicate that this function is
    rarely used by applications. The SSL_free_buffers function is used to free the internal OpenSSL buffer
    used when processing an incoming record from the network. The call is only expected to succeed if the
    buffer is not currently in use. However, two scenarios have been identified where the buffer is freed even
    when still in use. The first scenario occurs where a record header has been received from the network and
    processed by OpenSSL, but the full record body has not yet arrived. In this case calling SSL_free_buffers
    will succeed even though a record has only been partially processed and the buffer is still in use. The
    second scenario occurs where a full record containing application data has been received and processed by
    OpenSSL but the application has only read part of this data. Again a call to SSL_free_buffers will succeed
    even though the buffer is still in use. While these scenarios could occur accidentally during normal
    operation a malicious attacker could attempt to engineer a stituation where this occurs. We are not aware
    of this issue being actively exploited. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this
    issue. (CVE-2024-4741)

  - In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, due to a code logic error,
    filtering functions such as filter_var when validating URLs (FILTER_VALIDATE_URL) for certain types of
    URLs the function will result in invalid user information (username + password part of URLs) being treated
    as valid user information. This may lead to the downstream code accepting invalid URLs as valid and
    parsing them incorrectly. (CVE-2024-5458)

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
    in the next releases when they become available. (CVE-2024-5535)

  - In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, the fix for CVE-2024-1874
    does not work if the command name includes trailing spaces. Original issue: when using proc_open() command
    with array syntax, due to insufficient escaping, if the arguments of the executed command are controlled
    by a malicious user, the user can supply arguments that would execute arbitrary commands in Windows shell.
    (CVE-2024-5585)

  - Issue summary: Applications performing certificate name checks (e.g., TLS clients checking server
    certificates) may attempt to read an invalid memory address resulting in abnormal termination of the
    application process. Impact summary: Abnormal termination of an application can a cause a denial of
    service. Applications performing certificate name checks (e.g., TLS clients checking server certificates)
    may attempt to read an invalid memory address when comparing the expected name with an `otherName` subject
    alternative name of an X.509 certificate. This may result in an exception that terminates the application
    program. Note that basic certificate chain validation (signatures, dates, ...) is not affected, the denial
    of service can occur only when the application also specifies an expected DNS name, Email address or IP
    address. TLS servers rarely solicit client certificates, and even when they do, they generally don't
    perform a name check against a reference identifier (expected identity), but rather extract the presented
    identity after checking the certificate chain. So TLS servers are generally not affected and the severity
    of the issue is Moderate. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.
    (CVE-2024-6119)

  - Security Center leverages third-party software to help provide underlying functionality. Several of the
    third-party components (OpenSSL, PHP) were found to contain vulnerabilities, and updated versions have
    been made available by the providers.Out of caution and in line with best practice, Tenable has opted to
    upgrade these components to address the potential impact of the issues. Security Center Patch SC-202412.1
    updates OpenSSL to version 3.0.15 and PHP to version 8.2.26 to address the identified vulnerabilities.
    Tenable has released Security Center Patch SC-202412.1 to address these issues. The installation files can
    be obtained from the Tenable Downloads Portal: https://www.tenable.com/downloads/security-center
    (CVE-2024-8932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/security-center/2024.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94420b11");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2024-21");
  script_set_attribute(attribute:"solution", value:
"Apply Patch SC-202412.1");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list("SC-202412.1");
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '6.3.0', 'fixed_display' : 'Apply Patch SC-202412.1' },
  { 'equal' : '6.4.0', 'fixed_display' : 'Apply Patch SC-202412.1' },
  { 'equal' : '6.4.5', 'fixed_display' : 'Apply Patch SC-202412.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
