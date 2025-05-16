#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104408);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_bugtraq_id(100515);

  script_name(english:"OpenSSL 1.0.2 < 1.0.2m Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.0.2m. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1.0.2m advisory.

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL before 1.0.2m and
    1.1.0 before 1.1.0g. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as
    a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH
    are considered just feasible (although very difficult) because most of the work necessary to deduce
    information about a private key may be performed offline. The amount of resources required for such an
    attack would be very significant and likely only accessible to a limited number of attackers. An attacker
    would additionally need online access to an unpatched system using the target private key in a scenario
    with persistent DH parameters and a private key that is shared between multiple clients. This only affects
    processors that support the BMI1, BMI2 and ADX extensions like Intel Broadwell (5th generation) and later
    or AMD Ryzen. (CVE-2017-3736)

  - While parsing an IPAddressFamily extension in an X.509 certificate, it is possible to do a one-byte
    overread. This would result in an incorrect text display of the certificate. This bug has been present
    since 2006 and is present in all versions of OpenSSL before 1.0.2m and 1.1.0g. (CVE-2017-3735)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=31c8b265591a0aaa462a1f3eb5770661aaac67db
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?63dd892d");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=38d600147331d36e74174ebbd4008b63188b321b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f3f89798");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3735");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2017-3736");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170828.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20171102.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2m or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-3736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");

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
  { 'min_version' : '1.0.2', 'fixed_version' : '1.0.2m' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
