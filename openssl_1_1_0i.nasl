#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(112120);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/26");

  script_cve_id("CVE-2018-0732", "CVE-2018-0737", "CVE-2018-5407");
  script_bugtraq_id(103766, 104442);

  script_name(english:"OpenSSL 1.1.0 < 1.1.0i Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.0i. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.0i advisory.

  - Simultaneous Multi-threading (SMT) in processors can enable local users to exploit software vulnerable to
    timing attacks via a side-channel timing attack on 'port contention'. (CVE-2018-5407)

  - During key agreement in a TLS handshake using a DH(E) based ciphersuite a malicious server can send a very
    large prime value to the client. This will cause the client to spend an unreasonably long period of time
    generating a key for this prime resulting in a hang until the client has finished. This could be exploited
    in a Denial Of Service attack. Fixed in OpenSSL 1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in OpenSSL
    1.0.2p-dev (Affected 1.0.2-1.0.2o). (CVE-2018-0732)

  - The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel
    attack. An attacker with sufficient access to mount cache timing attacks during the RSA key generation
    process could recover the private key. Fixed in OpenSSL 1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in
    OpenSSL 1.0.2p-dev (Affected 1.0.2b-1.0.2o). (CVE-2018-0737)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=aab7c770353b1dc4ba045938c8fb446dd1c4531e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a1d82e9");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=6939eab03a6e23d2bd2c3f5e34fe1d48e542e787
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c736b9c1");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ea7abeeabf92b7aca160bdd0208636d4da69f4f4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca563bc3");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2018-0732");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2018-0737");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2018-5407");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20180612.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20180416.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20181112.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0i or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.1.0', 'fixed_version' : '1.1.0i' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
