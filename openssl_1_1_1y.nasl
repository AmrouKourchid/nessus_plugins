#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192965);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2024-2511", "CVE-2024-4741");
  script_xref(name:"IAVA", value:"2024-A-0208-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1y Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1y. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.1y advisory.

  - Issue summary: Some non-default TLS server configurations can cause unbounded memory growth when
    processing TLSv1.3 sessions Impact summary: An attacker may exploit certain server configurations to
    trigger unbounded memory growth that would lead to a Denial of Service This problem can occur in TLSv1.3
    if the non-default SSL_OP_NO_TICKET option is being used (but not if early_data support is also configured
    and the default anti-replay protection is in use). In this case, under certain conditions, the session
    cache can get into an incorrect state and it will fail to flush properly as it fills. The session cache
    will continue to grow in an unbounded manner. A malicious client could deliberately create the scenario
    for this failure to force a Denial of Service. It may also happen by accident in normal operation. This
    issue only affects TLS servers supporting TLSv1.3. It does not affect TLS clients. The FIPS modules in
    3.2, 3.1 and 3.0 are not affected by this issue. OpenSSL 1.0.2 is also not affected by this issue.
    (CVE-2024-2511)

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
    issue. Found by William Ahern (Akamai). Fix developed by Matt Caswell. Fix developed by Watson Ladd
    (Akamai). Fixed in OpenSSL 3.3.1 (Affected since 3.3.0). (CVE-2024-4741)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-2511");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-4741");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1y or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4741");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '1.1.1', 'fixed_version' : '1.1.1y' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
