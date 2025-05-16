#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(94963);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2016-7053", "CVE-2016-7054", "CVE-2016-7055");
  script_bugtraq_id(94238, 94242, 94244);

  script_name(english:"OpenSSL 1.1.0 < 1.1.0c Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.0c. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.1.0c advisory.

  - There is a carry propagating bug in the Broadwell-specific Montgomery multiplication procedure in OpenSSL
    1.0.2 and 1.1.0 before 1.1.0c that handles input lengths divisible by, but longer than 256 bits. Analysis
    suggests that attacks against RSA, DSA and DH private keys are impossible. This is because the subroutine
    in question is not used in operations with the private key itself and an input of the attacker's direct
    choice. Otherwise the bug can manifest itself as transient authentication and key negotiation failures or
    reproducible erroneous outcome of public-key operations with specially crafted input. Among EC algorithms
    only Brainpool P-512 curves are affected and one presumably can attack ECDH key negotiation. Impact was
    not analyzed in detail, because pre-requisites for attack are considered unlikely. Namely multiple clients
    have to choose the curve in question and the server has to share the private key among them, neither of
    which is default behaviour. Even then only clients that chose the curve will be affected. (CVE-2016-7055)

  - In OpenSSL 1.1.0 before 1.1.0c, TLS connections using *-CHACHA20-POLY1305 ciphersuites are susceptible to
    a DoS attack by corrupting larger payloads. This can result in an OpenSSL crash. This issue is not
    considered to be exploitable beyond a DoS. (CVE-2016-7054)

  - In OpenSSL 1.1.0 before 1.1.0c, applications parsing invalid CMS structures can crash with a NULL pointer
    dereference. This is caused by a bug in the handling of the ASN.1 CHOICE type in OpenSSL 1.1.0 which can
    result in a NULL value being passed to the structure callback if an attempt is made to free certain
    invalid encodings. Only CHOICE structures using a callback which do not handle NULL value are affected.
    (CVE-2016-7053)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=2a7dd548a6f5d6f7f84a89c98323b70a2822406e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5072107");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=99d97842ddb5fbbbfb5e9820a64ebd19afe569f6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db90cfd5");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=610b66267e41a32805ab54cbc580c5a6d5826cb4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e57daf59");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-7053");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-7054");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-7055");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20161110.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0c or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7054");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

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
  { 'min_version' : '1.1.0', 'fixed_version' : '1.1.0c' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
