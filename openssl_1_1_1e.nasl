#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200200);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2019-1551");
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1e Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1e. It is, therefore, affected by a vulnerability as
referenced in the 1.1.1e advisory.

  - There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit
    moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime
    RSA1536, and DSA1024 as a result of this defect would be very difficult to perform and are not believed
    likely. Attacks against DH512 are considered just feasible. However, for an attack the target would have
    to re-use the DH512 private key, which is not recommended anyway. Also applications directly using the low
    level API BN_mod_exp may be affected if they use BN_FLG_CONSTTIME. Fixed in OpenSSL 1.1.1e (Affected
    1.1.1-1.1.1d). Fixed in OpenSSL 1.0.2u (Affected 1.0.2-1.0.2t). (CVE-2019-1551)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=419102400a2811582a7a3d4a4e317d72e5ce0a8f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d01cae2c");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1551");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20191206.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1e or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '1.1.1', 'fixed_version' : '1.1.1e' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
