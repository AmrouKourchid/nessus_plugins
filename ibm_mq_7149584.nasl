#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194849);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2023-6237", "CVE-2024-0727");

  script_name(english:"IBM MQ 9.0 <= 9.0.0.24 / 9.1 <= 9.1.0.21 / 9.2 <= 9.2.0.25 / 9.3 <= 9.3.0.17 (7149584)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM MQ Server running on the remote host is affected by multiple vulnerabilities as referenced in the
7149584 advisory.

  - Issue summary: Checking excessively long invalid RSA public keys may take a long time. Impact summary:
    Applications that use the function EVP_PKEY_public_check() to check RSA public keys may experience long
    delays. Where the key that is being checked has been obtained from an untrusted source this may lead to a
    Denial of Service. When function EVP_PKEY_public_check() is called on RSA public keys, a computation is
    done to confirm that the RSA modulus, n, is composite. For valid RSA keys, n is a product of two or more
    large primes and this computation completes quickly. However, if n is an overly large prime, then this
    computation would take a long time. An application that calls EVP_PKEY_public_check() and supplies an RSA
    key obtained from an untrusted source could be vulnerable to a Denial of Service attack. The function
    EVP_PKEY_public_check() is not called from other OpenSSL functions however it is called from the OpenSSL
    pkey command line application. For that reason that application is also vulnerable if used with the
    '-pubin' and '-check' options on untrusted data. The OpenSSL SSL/TLS implementation is not affected by
    this issue. The OpenSSL 3.0 and 3.1 FIPS providers are affected by this issue. (CVE-2023-6237)

  - Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a
    potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from
    untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and
    may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL
    does not correctly check for this case. This can lead to a NULL pointer dereference that results in
    OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs
    then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are:
    PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and
    PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function
    is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and
    3.0 are not affected by this issue. (CVE-2024-0727)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7149584");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 9.0.0.24 CU9, 9.1.0.21 CU9, 9.2.0.25 CU9, 9.3.0.17 CU9 or later. Alternatively, install  where
appropriate.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:mq");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_mq_nix_installed.nbin", "websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');

var app = 'IBM WebSphere MQ';

var app_info = vcf::get_app_info(app:app);

if (app_info['Type'] != 'Server')
  audit(AUDIT_HOST_NOT, 'an affected product');

# Some versions require an interim fix, which we are not checking, so require paranoia for those versions only
if ((app_info['version'] =~ "^9.0.0.24" || app_info['version'] =~ "^9.1.0.21" || app_info['version'] =~ "^9.2.0.25" || app_info['version'] =~ "^9.3.0.17") && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, app, app_info['version']);
var constraints = [
  { 'min_version' : '9.0', 'max_version' : '9.0.0.24', 'fixed_display' : '9.0.0.24 CU9' },
  { 'min_version' : '9.1', 'max_version' : '9.1.0.21', 'fixed_display' : '9.1.0.21 CU9' },
  { 'min_version' : '9.2', 'max_version' : '9.2.0.25', 'fixed_display' : '9.2.0.25 CU9' },
  { 'min_version' : '9.3', 'max_version' : '9.3.0.17', 'fixed_display' : '9.3.0.17 CU9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
