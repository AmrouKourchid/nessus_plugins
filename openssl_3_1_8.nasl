#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209154);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-9143");
  script_xref(name:"IAVA", value:"2025-A-0127");

  script_name(english:"OpenSSL 3.1.0 < 3.1.8 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 3.1.8. It is, therefore, affected by a vulnerability as
referenced in the 3.1.8 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/fdf6723362ca51bd883295efe206cb5b1cfa5154
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f636435");
  script_set_attribute(attribute:"see_also", value:"https://openssl-library.org/news/secadv/20241016.txt");
  script_set_attribute(attribute:"see_also", value:"https://openssl-library.org/policies/general/security-policy/#low");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2024-9143");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 3.1.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '3.1.0', 'fixed_version' : '3.1.8' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
