#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17761);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2009-1386");
  script_bugtraq_id(35174);
  script_xref(name:"EDB-ID", value:"8873");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8i Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.8i. It is, therefore, affected by a vulnerability as
referenced in the 0.9.8i advisory.

  - ssl/s3_pkt.c in OpenSSL before 0.9.8i allows remote attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via a DTLS ChangeCipherSpec packet that occurs before ClientHello.
    (CVE-2009-1386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=1cbf663a6c89dcf8f7706d30a8bae675e2e0199a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f69832de");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2009-1386");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.8i or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-1386");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var constraints = [
  { 'min_version' : '0.9.8', 'fixed_version' : '0.9.8i' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
