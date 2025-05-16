#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190851);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id(
    "CVE-2023-5981",
    "CVE-2023-7104",
    "CVE-2024-0727",
    "CVE-2023-27043",
    "CVE-2023-5678"
  );

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.2010)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.2010 advisory.

  - A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified as critical. This issue affects
    the function sessionReadRecord of the file ext/session/sqlite3session.c of the component make alltest
    Handler. The manipulation leads to heap-based buffer overflow. It is recommended to apply a patch to fix
    this issue. The associated identifier of this vulnerability is VDB-248999. (CVE-2023-7104)

  - A vulnerability was found that the response times to malformed ciphertexts in RSA-PSK ClientKeyExchange
    differ from response times of ciphertexts with correct PKCS#1 v1.5 padding. (CVE-2023-5981)

  - The email module of Python through 3.11.3 incorrectly parses e-mail addresses that contain a special
    character. The wrong portion of an RFC2822 header is identified as the value of the addr-spec. In some
    applications, an attacker can bypass a protection mechanism in which application access is granted only
    after verifying receipt of e-mail to a specific domain (e.g., only @company.example.com addresses may be
    used for signup). This occurs in email/_parseaddr.py in recent versions of Python. (CVE-2023-27043)

  - Issue summary: Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or
    parameters may be very slow. Impact summary: Applications that use the functions DH_generate_key() to
    generate an X9.42 DH key may experience long delays. Likewise, applications that use DH_check_pub_key(),
    DH_check_pub_key_ex() or EVP_PKEY_public_check() to check an X9.42 DH key or X9.42 DH parameters may
    experience long delays. Where the key or parameters that are being checked have been obtained from an
    untrusted source this may lead to a Denial of Service. While DH_check() performs all the necessary checks
    (as of CVE-2023-3817), DH_check_pub_key() doesn't make any of these checks, and is therefore vulnerable
    for excessively large P and Q parameters. Likewise, while DH_generate_key() performs a check for an
    excessively large P, it doesn't check for an excessively large Q. An application that calls
    DH_generate_key() or DH_check_pub_key() and supplies a key or parameters obtained from an untrusted source
    could be vulnerable to a Denial of Service attack. DH_generate_key() and DH_check_pub_key() are also
    called by a number of other OpenSSL functions. An application calling any of those other functions may
    similarly be affected. The other functions affected by this are DH_check_pub_key_ex(),
    EVP_PKEY_public_check(), and EVP_PKEY_generate(). Also vulnerable are the OpenSSL pkey command line
    application when using the -pubcheck option, as well as the OpenSSL genpkey command line application.
    The OpenSSL SSL/TLS implementation is not affected by this issue. The OpenSSL 3.0 and 3.1 FIPS providers
    are not affected by this issue. (CVE-2023-5678)

  - Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a
    potential Denial of Service attack Impact summary: Applications loading files in the PKCS12 format from
    untrusted sources might terminate abruptly. A file in PKCS12 format can contain certificates and keys and
    may come from an untrusted source. The PKCS12 specification allows certain fields to be NULL, but OpenSSL
    does not correctly check for this case. This can lead to a NULL pointer dereference that results in
    OpenSSL crashing. If an application processes PKCS12 files from an untrusted source using the OpenSSL APIs
    then that application will be vulnerable to this issue. OpenSSL APIs that are vulnerable to this are:
    PKCS12_parse(), PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes() and
    PKCS12_newpass(). We have also fixed a similar issue in SMIME_write_PKCS7(). However since this function
    is related to writing data we do not consider it security significant. The FIPS modules in 3.2, 3.1 and
    3.0 are not affected by this issue. (CVE-2024-0727)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d9f1576");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-7104");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-5981");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20230302.102005', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20230302.102005 or higher.' }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
