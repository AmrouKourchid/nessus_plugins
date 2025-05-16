#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233860);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-2704");
  script_cwe_id("754");
  script_xref(name:"IAVA", value:"2025-A-0219");

  script_name(english:"OpenVPN Server versions 2.6.1 <= 2.6.13 DoS");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"OpenVPN from 2.6.1 through 2.6.13, setup with tls-crypt-v2. is affected by a denial of service vulnerability.  
A local attacker who can monitor network traffic, can inject specially crafted packets during the tls-crypt2-v2 handshake and 
corrupt the server.");
  # https://community.openvpn.net/openvpn/wiki/CVE-2025-2704
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?395dd159");
  script_set_attribute(attribute:"see_also", value:"https://www.openwall.com/lists/oss-security/2025/04/02/5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN Server 2.6.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2704");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_server_installed.nbin");
  script_require_keys("installed_sw/OpenVPN Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'OpenVPN Server');

# require paranoia due to tls-crypt_v2 settings required
var constraints = [
  {'min_version': '2.6.1', 'fixed_version': '2.6.14', require_paranoia:true}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
