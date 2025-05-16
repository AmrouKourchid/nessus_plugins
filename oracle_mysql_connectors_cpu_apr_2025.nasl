#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234560);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-9143",
    "CVE-2024-13176",
    "CVE-2025-30706",
    "CVE-2025-30714"
  );
  script_xref(name:"IAVA", value:"2025-A-0272");

  script_name(english:"Oracle MySQL Connectors (April 2025 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 9.0.0, 9.1.0 and 9.2.0 versions of MySQL Connectors installed on the remote host are affected by multiple vulnerabilities
as referenced in the April 2025 CPU advisory.

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

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/J). Supported versions
    that are affected are 9.0.0-9.2.0. Difficult to exploit vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise MySQL Connectors. Successful attacks of this
    vulnerability can result in takeover of MySQL Connectors. (CVE-2025-30706)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2025csaf.json");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2025.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9143");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_connectors");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_connectors_version_nix.nbin", "mysql_connectors_version_win.nbin");
  script_require_keys("installed_sw/MySQL Connector");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Connector');
var product = tolower(app_info['Product']);

vcf::check_granularity(app_info:app_info, sig_segments:3);

if ('mysql connector j' >!< product && 'c++' >!< product && 'odbc' >!< product && 'python' >!< product)
  audit(AUDIT_PACKAGE_NOT_AFFECTED, product);

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
