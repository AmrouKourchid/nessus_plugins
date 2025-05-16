#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17751);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2009-0653");

  script_name(english:"OpenSSL 0.9.6 CA Basic Constraints Validation Vulnerability");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a certificate validation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7. 

Such versions do not verify the Basic Constraint for some
certificates.  A remote attacker could perform a man-in-the-middle
attack. 

Details on this weakness are missing.  It is related to CVE-2002-0970. 
OpenSSL 0.9.6 was reported as 'probably' vulnerable.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e41b7c3");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0653");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2024 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : '0.0.0', 'fixed_version' : '0.9.7'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
