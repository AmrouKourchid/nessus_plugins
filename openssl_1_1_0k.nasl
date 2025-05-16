#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125642);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id("CVE-2019-1543");
  script_bugtraq_id(107349);

  script_name(english:"OpenSSL 1.1.0 < 1.1.0k Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.0k. It is, therefore, affected by a vulnerability as
referenced in the 1.1.0k advisory.

  - ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input for every encryption operation. RFC
    7539 specifies that the nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce
    length and front pads the nonce with 0 bytes if it is less than 12 bytes. However it also incorrectly
    allows a nonce to be set of up to 16 bytes. In this case only the last 12 bytes are significant and any
    additional leading bytes are ignored. It is a requirement of using this cipher that nonce values are
    unique. Messages encrypted using a reused nonce value are susceptible to serious confidentiality and
    integrity attacks. If an application changes the default nonce length to be longer than 12 bytes and then
    makes a change to the leading bytes of the nonce expecting the new value to be a new unique nonce then
    such an application could inadvertently encrypt messages with a reused nonce. Additionally the ignored
    bytes in a long nonce are not covered by the integrity guarantee of this cipher. Any application that
    relies on the integrity of these ignored leading bytes of a long nonce may be further affected. Any
    OpenSSL internal use of this cipher, including in SSL/TLS, is safe because no such use sets such a long
    nonce value. However user applications that use this cipher directly and set a non-default nonce length to
    be longer than 12 bytes may be vulnerable. OpenSSL versions 1.1.1 and 1.1.0 are affected by this issue.
    Due to the limited scope of affected deployments this has been assessed as low severity and therefore we
    are not creating new releases at this time. Fixed in OpenSSL 1.1.1c (Affected 1.1.1-1.1.1b). Fixed in
    OpenSSL 1.1.0k (Affected 1.1.0-1.1.0j). (CVE-2019-1543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ee22257b1418438ebaf54df98af4e24f494d1809
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e7e1fbf");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2019-1543");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190306.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0k or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1543");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl", "openssl_nix_installed.nbin", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '1.1.0', 'fixed_version' : '1.1.0k' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
