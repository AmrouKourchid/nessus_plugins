#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(45359);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2010-0433", "CVE-2010-0740");
  script_bugtraq_id(38533, 39013);
  script_xref(name:"Secunia", value:"38807");

  script_name(english:"OpenSSL 0.9.8 < 0.9.8n Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 0.9.8n. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0.9.8n advisory.

  - The ssl3_get_record function in ssl/s3_pkt.c in OpenSSL 0.9.8f through 0.9.8m allows remote attackers to
    cause a denial of service (crash) via a malformed record in a TLS connection that triggers a NULL pointer
    dereference, related to the minor version number. NOTE: some of these details are obtained from third
    party information. (CVE-2010-0740)

  - The kssl_keytab_is_available function in ssl/kssl.c in OpenSSL before 0.9.8n, when Kerberos is enabled but
    Kerberos configuration files cannot be opened, does not check a certain return value, which allows remote
    attackers to cause a denial of service (NULL pointer dereference and daemon crash) via SSL cipher
    negotiation, as demonstrated by a chroot installation of Dovecot or stunnel without Kerberos configuration
    files inside the chroot. (CVE-2010-0433)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=cca1cd9a3447dd067503e4a85ebd1679ee78a48e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?258ebd83");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2010-0433");
  script_set_attribute(attribute:"see_also", value:"https://www.cve.org/CVERecord?id=CVE-2010-0740");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20100324.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 0.9.8n or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0740");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("openssl_nix_installed.nbin", "openssl_version.nasl", "openssl_win_installed.nbin");
  script_require_keys("installed_sw/OpenSSL");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_openssl.inc');

var app_info = vcf::combined_get_app_info(app:'OpenSSL');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '0.9.8', 'fixed_version' : '0.9.8n' },
  { 'min_version' : '0.9.8f', 'fixed_version' : '0.9.8n' }
];

vcf::openssl::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
