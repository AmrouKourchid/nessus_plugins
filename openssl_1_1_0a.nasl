#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93816);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6307",
    "CVE-2016-6308"
  );
  script_bugtraq_id(
    93149,
    93150,
    93151,
    93152
  );

  script_name(english:"OpenSSL 1.1.0 < 1.1.0a Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.0a. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.0a advisory.

  - The ssl3_read_bytes function in record/rec_layer_s3.c in OpenSSL 1.1.0 before 1.1.0a allows remote
    attackers to cause a denial of service (infinite loop) by triggering a zero-length record in an SSL_peek
    call. (CVE-2016-6305)

  - Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a
    allow remote attackers to cause a denial of service (memory consumption) via large OCSP Status Request
    extensions. (CVE-2016-6304)

  - statem/statem_dtls.c in the DTLS implementation in OpenSSL 1.1.0 before 1.1.0a allocates memory before
    checking for an excessive length, which might allow remote attackers to cause a denial of service (memory
    consumption) via crafted DTLS messages. (CVE-2016-6308)

  - The state-machine implementation in OpenSSL 1.1.0 before 1.1.0a allocates memory before checking for an
    excessive length, which might allow remote attackers to cause a denial of service (memory consumption) via
    crafted TLS messages, related to statem/statem.c and statem/statem_lib.c. (CVE-2016-6307)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160922.txt");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=63658103d4441924f8dbfc517b99bb54758a98b9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38bae510");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=a59ab1c4dd27a4c7c6e88f3c33747532fd144412
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b35a180d");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=df6b5e29ffea2d5a3e08de92fb765fdb21c7a21e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eef590aa");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=4b390b6c3f8df925dc92a3dd6b022baa9a2f4650
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff41663f");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6304");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6305");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6307");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-6308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0a or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-6305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.1.0', 'fixed_version' : '1.1.0a' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
