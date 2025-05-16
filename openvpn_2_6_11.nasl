#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208125);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id("CVE-2024-28882");
  script_xref(name:"IAVA", value:"2024-A-0608-S");

  script_name(english:"OpenVPN Server versions 2.6.0 <= 2.6.10 Session Extension Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by CVE-2024-2882.");
  script_set_attribute(attribute:"description", value:
"OpenVPN from 2.6.0 through 2.6.10 in a server role accepts multiple exit notifications from authenticated clients 
 which will extend the validity of a closing session");
  # https://community.openvpn.net/openvpn/wiki/VulnerabilitiesFixedInOpenVPN243
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af9c7e6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenVPN Server 2.6.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openvpn_server_installed.nbin");
  script_require_keys("installed_sw/OpenVPN Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'OpenVPN Server');

var constraints = [
  {'min_version': '2.6.0', 'fixed_version': '2.6.11'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
