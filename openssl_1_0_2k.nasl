#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96873);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");
  script_bugtraq_id(94242, 95813, 95814);

  script_name(english:"OpenSSL 1.0.2 < 1.0.2k Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2k. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2k advisory.

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL 1.0.2 before
    1.0.2k and 1.1.0 before 1.1.0d. No EC algorithms are affected. Analysis suggests that attacks against RSA
    and DSA as a result of this defect would be very difficult to perform and are not believed likely. Attacks
    against DH are considered just feasible (although very difficult) because most of the work necessary to
    deduce information about a private key may be performed offline. The amount of resources required for such
    an attack would be very significant and likely only accessible to a limited number of attackers. An
    attacker would additionally need online access to an unpatched system using the target private key in a
    scenario with persistent DH parameters and a private key that is shared between multiple clients. For
    example this can occur by default in OpenSSL DHE based SSL/TLS ciphersuites. Note: This issue is very
    similar to CVE-2015-3193 but must be treated as a separate problem. (CVE-2017-3732)

  - If an SSL/TLS server or client is running on a 32-bit host, and a specific cipher is being used, then a
    truncated packet can cause that server or client to perform an out-of-bounds read, usually resulting in a
    crash. For OpenSSL 1.1.0, the crash can be triggered when using CHACHA20/POLY1305; users should upgrade to
    1.1.0d. For Openssl 1.0.2, the crash can be triggered when using RC4-MD5; users who have not disabled that
    algorithm should update to 1.0.2k. (CVE-2017-3731)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=760d04342a495ee86bf5adc71a91d126af64397f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c17ebc8");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=57c4b9f6a2f800b41ce2836986fe33640f6c3f8a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?709c1da4");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=51d009043670a627d6abe66894126851cf3690e9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8d771b1");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2016-7055");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3731");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3732");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20161110.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170126.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2k or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2k' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
