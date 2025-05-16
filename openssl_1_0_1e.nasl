#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64620);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1e Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote service may be affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running a version of
OpenSSL 1.0.1 prior to 1.0.1e.  The OpenSSL library is, therefore,
reportedly affected by an incomplete fix for CVE-2013-0169.

An error exists related to the SSL/TLS/DTLS protocols, CBC mode
encryption and response time.  An attacker could obtain plaintext
contents of encrypted traffic via timing attacks.");
  # https://www.mail-archive.com/openssl-announce@openssl.org/msg00125.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9167fa5f");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=0c4b72e9c0e3a75e0b89166540396dc3b58138b8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7f8a0c1");
  # https://git.openssl.org/gitweb/?p=openssl-web.git;a=commitdiff;h=3668d99f1db0410ccd43b5edb88651ccf6e9ac48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecf84273");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL 1.0.1e or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2024 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [{ 'min_version' : "1.0.1", 'fixed_version' : '1.0.1e'}];

vcf::openssl::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
