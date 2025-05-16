#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57460);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2011-4108",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619",
    "CVE-2012-0027"
  );
  script_bugtraq_id(51281);

  script_name(english:"OpenSSL 1.0.0 < 1.0.0f Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.0f. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.0f advisory.

  - The GOST ENGINE in OpenSSL before 1.0.0f does not properly handle invalid parameters for the GOST block
    cipher, which allows remote attackers to cause a denial of service (daemon crash) via crafted data from a
    TLS client. (CVE-2012-0027)

  - The Server Gated Cryptography (SGC) implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f does not
    properly handle handshake restarts, which allows remote attackers to cause a denial of service (CPU
    consumption) via unspecified vectors. (CVE-2011-4619)

  - OpenSSL before 0.9.8s and 1.x before 1.0.0f, when RFC 3779 support is enabled, allows remote attackers to
    cause a denial of service (assertion failure) via an X.509 certificate containing certificate-extension
    data associated with (1) IP address blocks or (2) Autonomous System (AS) identifiers. (CVE-2011-4577)

  - The SSL 3.0 implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f does not properly initialize
    data structures for block cipher padding, which might allow remote attackers to obtain sensitive
    information by decrypting the padding data sent by an SSL peer. (CVE-2011-4576)

  - The DTLS implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f performs a MAC check only if
    certain padding is valid, which makes it easier for remote attackers to recover plaintext via a padding
    oracle attack. (CVE-2011-4108)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20120104.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2011-4108");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2011-4576");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2011-4577");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2011-4619");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2012-0027");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.0f or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-4576");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-0027");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/09");

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
  { 'min_version' : '1.0.0', 'fixed_version' : '1.0.0f' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
