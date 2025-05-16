#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178476);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2023-3446", "CVE-2023-3817");
  script_xref(name:"IAVA", value:"2023-A-0398-S");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2zi Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2zi. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2zi advisory.

  - Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary:
    Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key
    or DH parameters may experience long delays. Where the key or parameters that are being checked have been
    obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs
    various checks on DH parameters. After fixing CVE-2023-3446 it was discovered that a large q parameter
    value can also trigger an overly long computation during some of these checks. A correct q value, if
    present, cannot be larger than the modulus p parameter, thus it is unnecessary to perform these checks if
    q is larger than p. An application that calls DH_check() and supplies a key or parameters obtained from an
    untrusted source could be vulnerable to a Denial of Service attack. The function DH_check() is itself
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_ex() and EVP_PKEY_param_check().
    Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications when using the -check
    option. The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS
    providers are not affected by this issue. (CVE-2023-3817)

  - Issue summary: Checking excessively long DH keys or parameters may be very slow. Impact summary:
    Applications that use the functions DH_check(), DH_check_ex() or EVP_PKEY_param_check() to check a DH key
    or DH parameters may experience long delays. Where the key or parameters that are being checked have been
    obtained from an untrusted source this may lead to a Denial of Service. The function DH_check() performs
    various checks on DH parameters. One of those checks confirms that the modulus ('p' parameter) is not too
    large. Trying to use a very large modulus is slow and OpenSSL will not normally use a modulus which is
    over 10,000 bits in length. However the DH_check() function checks numerous aspects of the key or
    parameters that have been supplied. Some of those checks use the supplied modulus value even if it has
    already been found to be too large. An application that calls DH_check() and supplies a key or parameters
    obtained from an untrusted source could be vulernable to a Denial of Service attack. The function
    DH_check() is itself called by a number of other OpenSSL functions. An application calling any of those
    other functions may similarly be affected. The other functions affected by this are DH_check_ex() and
    EVP_PKEY_param_check(). Also vulnerable are the OpenSSL dhparam and pkeyparam command line applications
    when using the '-check' option. The OpenSSL SSL/TLS implementation is not affected by this issue. The
    OpenSSL 3.0 and 3.1 FIPS providers are not affected by this issue. (CVE-2023-3446)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230719.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20230731.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/policies/secpolicy.html");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-3446");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2023-3817");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2zi or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2zi' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
