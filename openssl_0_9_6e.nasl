#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17746);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0659");
  script_bugtraq_id(
    5362,
    5363,
    5364,
    5366
  );
  script_xref(name:"CERT-CC", value:"CA-2002-23");
  script_xref(name:"CERT", value:"102795");
  script_xref(name:"CERT", value:"308891");

  script_name(english:"OpenSSL 0.9.6 < 0.9.6e Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.6e. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0.9.6e advisory.

  - The ASN1 library in OpenSSL 0.9.6d and earlier, and 0.9.7-beta2 and earlier, allows remote attackers to
    cause a denial of service via invalid encodings. (CVE-2002-0659)

  - Buffer overflows in OpenSSL 0.9.6d and earlier, and 0.9.7-beta2 and earlier, allow remote attackers to
    execute arbitrary code via (1) a large client master key in SSL2 or (2) a large session ID in SSL3.
    (CVE-2002-0656)

  - OpenSSL 0.9.6d and earlier, and 0.9.7-beta2 and earlier, does not properly handle ASCII representations of
    integers on 64 bit platforms, which could allow attackers to cause a denial of service and possibly
    execute arbitrary code. (CVE-2002-0655)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2002-0655");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2002-0656");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2002-0659");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20020730.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.6e or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-0655");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/30");
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
  { 'min_version' : '0.9.6', 'fixed_version' : '0.9.6e' },
  { 'min_version' : '0.9.6a', 'fixed_version' : '0.9.6e' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
