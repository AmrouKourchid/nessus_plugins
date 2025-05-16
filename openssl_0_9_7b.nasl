#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200199);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2003-0131", "CVE-2003-0147");

  script_name(english:"OpenSSL 0.9.7 < 0.9.7b Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.7b. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0.9.7b advisory.

  - The SSL and TLS components for OpenSSL 0.9.6i and earlier, 0.9.7, and 0.9.7a allow remote attackers to
    perform an unauthorized RSA private key operation via a modified Bleichenbacher attack that uses a large
    number of SSL or TLS connections using PKCS #1 v1.5 padding that cause OpenSSL to leak information
    regarding the relationship between ciphertext and the associated plaintext, aka the Klima-Pokorny-Rosa
    attack. (CVE-2003-0131)

  - OpenSSL does not use RSA blinding by default, which allows local and remote attackers to obtain the
    server's private key by determining factors using timing differences on (1) the number of extra reductions
    during Montgomery reduction, and (2) the use of different integer multiplication algorithms (Karatsuba
    and normal). (CVE-2003-0147)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2003-0131");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20030319.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2003-0147");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20030317.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.7b or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/14");
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
  { 'min_version' : '0.9.7', 'fixed_version' : '0.9.7b' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
