#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200205);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2006-2937",
    "CVE-2006-2940",
    "CVE-2006-3738",
    "CVE-2006-4343"
  );

  script_name(english:"OpenSSL 0.9.7 < 0.9.7l Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.7l. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0.9.7l advisory.

  - The get_server_hello function in the SSLv2 client code in OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before
    0.9.8d, and earlier versions allows remote servers to cause a denial of service (client crash) via unknown
    vectors that trigger a null pointer dereference. (CVE-2006-4343)

  - Buffer overflow in the SSL_get_shared_ciphers function in OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before
    0.9.8d, and earlier versions has unspecified impact and remote attack vectors involving a long list of
    ciphers. (CVE-2006-3738)

  - OpenSSL 0.9.7 before 0.9.7l, 0.9.8 before 0.9.8d, and earlier versions allows attackers to cause a denial
    of service (CPU consumption) via parasitic public keys with large (1) public exponent or (2) public
    modulus values in X.509 certificates that require extra time to process when using RSA signature
    verification. (CVE-2006-2940)

  - OpenSSL 0.9.7 before 0.9.7l and 0.9.8 before 0.9.8d allows remote attackers to cause a denial of service
    (infinite loop and memory consumption) via malformed ASN.1 structures that trigger an improperly handled
    error condition. (CVE-2006-2937)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2006-4343");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20060928.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2006-3738");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2006-2940");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2006-2937");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.7l or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3738");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2006-4343");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '0.9.7', 'fixed_version' : '0.9.7l' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
