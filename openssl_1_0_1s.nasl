#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(89081);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2016-0702",
    "CVE-2016-0705",
    "CVE-2016-0797",
    "CVE-2016-0798",
    "CVE-2016-0799",
    "CVE-2016-0800"
  );
  script_bugtraq_id(
    83705,
    83733,
    83754,
    83755,
    83763
  );
  script_xref(name:"CERT", value:"583776");

  script_name(english:"OpenSSL 1.0.1 < 1.0.1s Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.1s. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.1s advisory.

  - The SSLv2 protocol, as used in OpenSSL before 1.0.1s and 1.0.2 before 1.0.2g and other products, requires
    a server to send a ServerVerify message before establishing that a client possesses certain plaintext RSA
    data, which makes it easier for remote attackers to decrypt TLS ciphertext data by leveraging a
    Bleichenbacher RSA padding oracle, aka a DROWN attack. (CVE-2016-0800)

  - The fmtstr function in crypto/bio/b_print.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g
    improperly calculates string lengths, which allows remote attackers to cause a denial of service (overflow
    and out-of-bounds read) or possibly have unspecified other impact via a long string, as demonstrated by a
    large amount of ASN.1 data, a different vulnerability than CVE-2016-2842. (CVE-2016-0799)

  - Memory leak in the SRP_VBASE_get_by_user implementation in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before
    1.0.2g allows remote attackers to cause a denial of service (memory consumption) by providing an invalid
    username in a connection attempt, related to apps/s_server.c and crypto/srp/srp_vfy.c. (CVE-2016-0798)

  - Multiple integer overflows in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g allow remote attackers
    to cause a denial of service (heap memory corruption or NULL pointer dereference) or possibly have
    unspecified other impact via a long digit string that is mishandled by the (1) BN_dec2bn or (2) BN_hex2bn
    function, related to crypto/bn/bn.h and crypto/bn/bn_print.c. (CVE-2016-0797)

  - Double free vulnerability in the dsa_priv_decode function in crypto/dsa/dsa_ameth.c in OpenSSL 1.0.1
    before 1.0.1s and 1.0.2 before 1.0.2g allows remote attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact via a malformed DSA private key. (CVE-2016-0705)

  - The MOD_EXP_CTIME_COPY_FROM_PREBUF function in crypto/bn/bn_exp.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2
    before 1.0.2g does not properly consider cache-bank access times during modular exponentiation, which
    makes it easier for local users to discover RSA keys by running a crafted application on the same Intel
    Sandy Bridge CPU core as a victim and leveraging cache-bank conflicts, aka a CacheBleed attack.
    (CVE-2016-0702)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0702");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0705");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0797");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0798");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0799");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-0800");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.1s or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0799");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");

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
  { 'min_version' : '1.0.1', 'fixed_version' : '1.0.1s' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
