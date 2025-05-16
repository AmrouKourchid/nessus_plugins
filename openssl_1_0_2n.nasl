#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105291);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2017-3737", "CVE-2017-3738");
  script_bugtraq_id(102103, 102118);

  script_name(english:"OpenSSL 1.0.2 < 1.0.2n Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2n. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2n advisory.

  - There is an overflow bug in the AVX2 Montgomery multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to perform and are not believed likely. Attacks against
    DH1024 are considered just feasible, because most of the work necessary to deduce information about a
    private key may be performed offline. The amount of resources required for such an attack would be
    significant. However, for an attack on TLS to be meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions like Intel Haswell (4th generation). Note: The
    impact from this issue is similar to CVE-2017-3736, CVE-2017-3732 and CVE-2015-3193. OpenSSL version
    1.0.2-1.0.2m and 1.1.0-1.1.0g are affected. Fixed in OpenSSL 1.0.2n. Due to the low severity of this issue
    we are not issuing a new release of OpenSSL 1.1.0 at this time. The fix will be included in OpenSSL 1.1.0h
    when it becomes available. The fix is also available in commit e502cc86d in the OpenSSL git repository.
    (CVE-2017-3738)

  - OpenSSL 1.0.2 (starting from version 1.0.2b) introduced an error state mechanism. The intent was that if
    a fatal error occurred during a handshake then OpenSSL would move into the error state and would
    immediately fail if you attempted to continue the handshake. This works as designed for the explicit
    handshake functions (SSL_do_handshake(), SSL_accept() and SSL_connect()), however due to a bug it does not
    work correctly if SSL_read() or SSL_write() is called directly. In that scenario, if the handshake fails
    then a fatal error will be returned in the initial function call. If SSL_read()/SSL_write() is
    subsequently called by the application for the same SSL object then it will succeed and the data is passed
    without being decrypted/encrypted directly from the SSL/TLS record layer. In order to exploit this issue
    an application bug would have to be present that resulted in a call to SSL_read()/SSL_write() being issued
    after having already received a fatal error. OpenSSL version 1.0.2b-1.0.2m are affected. Fixed in OpenSSL
    1.0.2n. OpenSSL 1.1.0 is not affected. (CVE-2017-3737)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=898fb884b706aaeb283de4812340bb0bde8476dc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c95b768");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ca51bafc1a88d8b8348f5fd97adc5d6ca93f8e76
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abd19a43");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3737");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3738");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2n or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

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
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2n' },
  { 'min_version' : '1.0.2b', 'fixed_version' : '1.0.2n' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
