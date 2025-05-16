#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id(
    "CVE-2024-6197",
    "CVE-2024-6874",
    "CVE-2024-7264",
    "CVE-2024-8096",
    "CVE-2024-9143",
    "CVE-2024-9681",
    "CVE-2024-11053",
    "CVE-2024-13176",
    "CVE-2025-0167",
    "CVE-2025-0665",
    "CVE-2025-0725",
    "CVE-2025-1217",
    "CVE-2025-1219",
    "CVE-2025-1734",
    "CVE-2025-1736",
    "CVE-2025-1861"
  );

  script_name(english:"Tenable Security Center Multiple Vulnerabilities (TNS-2025-04)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Security Center installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Security Center running on the remote host is version 6.3.0, 6.4.0, 6.4.5, or 6.5.1. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2025-04 advisory.

  - When curl is asked to use HSTS, the expiry time for a subdomain might overwrite a parent domain's cache
    entry, making it end sooner or later than otherwise intended. This affects curl using applications that
    enable HSTS and use URLs with the insecure `HTTP://` scheme and perform transfers with hosts like
    `x.example.com` as well as `example.com` where the first host is a subdomain of the second host. (The HSTS
    cache either needs to have been populated manually or there needs to have been previous HTTPS accesses
    done as the cache needs to have entries for the domains involved to trigger this problem.) When
    `x.example.com` responds with `Strict-Transport-Security:` headers, this bug can make the subdomain's
    expiry timeout *bleed over* and get set for the parent domain `example.com` in curl's HSTS cache. The
    result of a triggered bug is that HTTP accesses to `example.com` get converted to HTTPS for a different
    period of time than what was asked for by the origin server. If `example.com` for example stops supporting
    HTTPS at its expiry time, curl might then fail to access `http://example.com` until the (wrongly set)
    timeout expires. This bug can also expire the parent's entry *earlier*, thus making curl inadvertently
    switch back to insecure HTTP earlier than otherwise intended. (CVE-2024-9681)

  - Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the field polynomial
    can lead to out-of-bounds memory reads or writes. (CVE-2024-9143)

  - Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the
    field polynomial can lead to out-of-bounds memory reads or writes. Impact summary: Out of bound memory
    writes can lead to an application crash or even a possibility of a remote code execution, however, in all
    the protocols involving Elliptic Curve Cryptography that we're aware of, either only named curves are
    supported, or, if explicit curve parameters are supported, they specify an X9.62 encoding of binary
    (GF(2^m)) curves that can't represent problematic input values. Thus the likelihood of existence of a
    vulnerable application is low. In particular, the X9.62 encoding is used for ECC keys in X.509
    certificates, so problematic inputs cannot occur in the context of processing X.509 certificates. Any
    problematic use-cases would have to be using an exotic curve encoding. The affected APIs include:
    EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(), and various supporting BN_GF2m_*() functions.
    Applications working with exotic explicit binary (GF(2^m)) curve parameters, that make it possible to
    represent invalid field polynomials with a zero constant term, via the above or similar APIs, may
    terminate abruptly as a result of reading or writing outside of array bounds. Remote code execution cannot
    easily be ruled out. The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.
    (CVE-2024-9143)

  - When asked to both use a `.netrc` file for credentials and to follow HTTP redirects, curl could leak the
    password used for the first host to the followed-to host under certain circumstances. This flaw only
    manifests itself if the netrc file has an entry that matches the redirect target hostname but the entry
    either omits just the password or omits both login and password. (CVE-2024-11053)

  - Issue summary: A timing side-channel which could potentially allow recovering the private key exists in
    the ECDSA signature computation. Impact summary: A timing side-channel in ECDSA signature computations
    could allow recovering the private key by an attacker. However, measuring the timing would require either
    local access to the signing application or a very fast network connection with low latency. There is a
    timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce value is zero. This
    can happen with significant probability only for some of the supported elliptic curves. In particular the
    NIST P-521 curve is affected. To be able to measure this leak, the attacker process must either be located
    in the same physical computer or must have a very fast network connection with low latency. For that
    reason the severity of this vulnerability is Low. The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are
    affected by this issue. (CVE-2024-13176)

  - libcurl's ASN1 parser has this utf8asn1str() function used for parsing an ASN.1 UTF-8 string. Itcan detect
    an invalid field and return error. Unfortunately, when doing so it also invokes `free()` on a 4 byte
    localstack buffer. Most modern malloc implementations detect this error and immediately abort. Some
    however accept the input pointer and add that memory to its list of available chunks. This leads to the
    overwriting of nearby stack memory. The content of the overwrite is decided by the `free()`
    implementation; likely to be memory pointers and a set of flags. The most likely outcome of exploting this
    flaw is a crash, although it cannot be ruled out that more serious results can be had in special
    circumstances. (CVE-2024-6197)

  - libcurl's URL API function [curl_url_get()](https://curl.se/libcurl/c/curl_url_get.html) offers punycode
    conversions, to and from IDN. Asking to convert a name that is exactly 256 bytes, libcurl ends up reading
    outside of a stack based buffer when built to use the *macidn* IDN backend. The conversion function then
    fills up the provided buffer exactly - but does not null terminate the string. This flaw can lead to stack
    contents accidently getting returned as part of the converted string. (CVE-2024-6874)

  - libcurl's ASN1 parser code has the `GTime2str()` function, used for parsing an ASN.1 Generalized Time
    field. If given an syntactically incorrect field, the parser might end up using -1 for the length of the
    *time fraction*, leading to a `strlen()` getting performed on a pointer to a heap buffer area that is not
    (purposely) null terminated. This flaw most likely leads to a crash, but can also lead to heap contents
    getting returned to the application when
    [CURLINFO_CERTINFO](https://curl.se/libcurl/c/CURLINFO_CERTINFO.html) is used. (CVE-2024-7264)

  - When curl is told to use the Certificate Status Request TLS extension, often referred to as OCSP stapling,
    to verify that the server certificate is valid, it might fail to detect some OCSP problems and instead
    wrongly consider the response as fine. If the returned status reports another error than 'revoked' (like
    for example 'unauthorized') it is not treated as a bad certficate. (CVE-2024-8096)

  - When asked to use a `.netrc` file for credentials **and** to follow HTTP redirects, curl could leak the
    password used for the first host to the followed-to host under certain circumstances. This flaw only
    manifests itself if the netrc file has a `default` entry that omits both login and password. A rare
    circumstance. (CVE-2025-0167)

  - libcurl would wrongly close the same eventfd file descriptor twice when taking down a connection channel
    after having completed a threaded name resolve. (CVE-2025-0665)

  - When libcurl is asked to perform automatic gzip decompression of content-encoded HTTP responses with the
    `CURLOPT_ACCEPT_ENCODING` option, **using zlib 1.2.0.3 or older**, an attacker-controlled integer overflow
    would make libcurl perform a buffer overflow. (CVE-2025-0725)

  - In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before
    8.4.5, when http request module parses HTTP response obtained from a server, folded headers are parsed
    incorrectly, which may lead to misinterpreting the response and using incorrect headers, MIME types, etc.
    (CVE-2025-1217)

  - In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before
    8.4.5, when requesting a HTTP resource using the DOM or SimpleXML extensions, the wrong content-type
    header is used to determine the charset when the requested resource performs a redirect. This may cause
    the resulting document to be parsed incorrectly or bypass validations. (CVE-2025-1219)

  - In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before
    8.4.5, when receiving headers from HTTP server, the headers missing a colon (:) are treated as valid
    headers even though they are not. This may confuse applications into accepting invalid headers.
    (CVE-2025-1734)

  - In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before
    8.4.5, when user-supplied headers are sent, the insufficient validation of the end-of-line characters may
    prevent certain headers from being sent or lead to certain headers be misinterpreted. (CVE-2025-1736)

  - In PHP from 8.1.* before 8.1.32, from 8.2.* before 8.2.28, from 8.3.* before 8.3.19, from 8.4.* before
    8.4.5, when parsing HTTP redirect in the response to an HTTP request, there is currently limit on the
    location value size caused by limited size of the location buffer to 1024. However as per RFC9110, the
    limit is recommended to be 8000. This may lead to incorrect URL truncation and redirecting to a wrong
    location. (CVE-2025-1861)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/security-center/2025.htm#2025042
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706a7506");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2025-04");
  script_set_attribute(attribute:"solution", value:
"Apply Patch SC-202504.2");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9143");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-9681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("installed_sw/SecurityCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::tenable_sc::get_app_info();

var patches = make_list("SC-202504.2");
vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'equal' : '6.3.0', 'fixed_display' : 'Apply Patch SC-202504.2' },
  { 'equal' : '6.4.0', 'fixed_display' : 'Apply Patch SC-202504.2' },
  { 'equal' : '6.4.5', 'fixed_display' : 'Apply Patch SC-202504.2' },
  { 'equal' : '6.5.1', 'fixed_display' : 'Apply Patch SC-202504.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
