#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105292);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-3738", "CVE-2018-0733", "CVE-2018-0739");
  script_bugtraq_id(102118, 103518);

  script_name(english:"OpenSSL 1.1.0 < 1.1.0h Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.0h. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.0h advisory.

  - Constructed ASN.1 types with a recursive definition (such as can be found in PKCS7) could eventually
    exceed the stack given malicious input with excessive recursion. This could result in a Denial Of Service
    attack. There are no such structures used within SSL/TLS that come from untrusted sources so this is
    considered safe. Fixed in OpenSSL 1.1.0h (Affected 1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected
    1.0.2b-1.0.2n). (CVE-2018-0739)

  - Because of an implementation bug the PA-RISC CRYPTO_memcmp function is effectively reduced to only
    comparing the least significant bit of each byte. This allows an attacker to forge messages that would be
    considered as authenticated in an amount of tries lower than that guaranteed by the security claims of the
    scheme. The module can only be compiled by the HP-UX assembler, so that only HP-UX PA-RISC targets are
    affected. Fixed in OpenSSL 1.1.0h (Affected 1.1.0-1.1.0g). (CVE-2018-0733)

  - There is an overflow bug in the AVX2 Montgomery multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to perform and are not believed likely. Attacks against
    DH1024 are considered just feasible, because most of the work necessary to deduce information about a
    private key may be performed offline. The amount of resources required for such an attack would be
    significant. However, for an attack on TLS to be meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions like Intel Haswell (4th generation). Note: The
    impact from this issue is similar to CVE-2017-3736, CVE-2017-3732 and CVE-2015-3193. OpenSSL version
    1.0.2-1.0.2m and 1.1.0-1.1.0g are affected. Fixed in OpenSSL 1.0.2n. Due to the low severity of this issue
    we are not issuing a new release of OpenSSL 1.1.0 at this time. The fix will be included in OpenSSL 1.1.0h
    when it becomes available. The fix is also available in commit e502cc86d in the OpenSSL git repository.
    (CVE-2017-3738)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2ac4c6f7b2b2af20c0e2b0ba05367e454cd11b33
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?283a3313");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=56d5a4bfcaf37fa420aef2bb881aa55e61cf5f2f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4648c39c");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e502cc86df9dafded1694fceb3228ee34d11c11a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c1eea34");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3738");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2018-0733");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2018-0739");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20180327.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0h or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0733");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.1.0', 'fixed_version' : '1.1.0h' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
