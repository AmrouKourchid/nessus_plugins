#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122504);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2019-1559");
  script_bugtraq_id(107174);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"OpenSSL 1.0.2 < 1.0.2r Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2r. It is, therefore, affected by a vulnerability as
referenced in the 1.0.2r advisory.

  - If an application encounters a fatal protocol error and then calls SSL_shutdown() twice (once to send a
    close_notify, and once to receive one) then OpenSSL can respond differently to the calling application if
    a 0 byte record is received with invalid padding compared to if a 0 byte record is received with an
    invalid MAC. If the application then behaves differently based on that in a way that is detectable to the
    remote peer, then this amounts to a padding oracle that could be used to decrypt data. In order for this
    to be exploitable non-stitched ciphersuites must be in use. Stitched ciphersuites are optimised
    implementations of certain commonly used ciphersuites. Also the application must call SSL_shutdown() twice
    even if a protocol error has occurred (applications should not do this but some do anyway). Fixed in
    OpenSSL 1.0.2r (Affected 1.0.2-1.0.2q). (CVE-2019-1559)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=e9bbefbf0f24c57645e7ad6a5a71ae649d18ac8e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?015dc646");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1559");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190226.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2r or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2r' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
