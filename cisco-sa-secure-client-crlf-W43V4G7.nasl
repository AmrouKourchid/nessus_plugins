#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191708);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id("CVE-2024-20337");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi37512");
  script_xref(name:"CISCO-SA", value:"cisco-sa-secure-client-crlf-W43V4G7");
  script_xref(name:"IAVA", value:"2024-A-0139");

  script_name(english:"Cisco Secure Client Carriage Return Line Feed Injection (cisco-sa-secure-client-crlf-W43V4G7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Client, formerly AnyConnect Secure Mobility Client, is affected by
a vulnerability in the SAML authentication process of Cisco Secure Client. The vulnerability could allow an
unauthenticated, remote attacker to conduct a carriage return line feed (CRLF) injection attack against a user. This
vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by
persuading a user to click a crafted link while establishing a VPN session. A successful exploit could allow the
attacker to execute arbitrary script code in the browser or access sensitive, browser-based information, including a
valid SAML token. The attacker could then use the token to establish a remote access VPN session with the privileges of
the affected user. Individual hosts and services behind the VPN headend would still need additional credentials for
successful access.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secure-client-crlf-W43V4G7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe1890ee");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi37512");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi37512");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(93);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl", "cisco_anyconnect_client_nix_installed.nbin", "macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client");

  exit(0);
}

include('vcf.inc');

var win_local;
if (get_kb_item('SMB/Registry/Enumerated'))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:win_local);

var constraints = [
  { 'min_version' : '4.10.04065', 'fixed_version': '4.10.08025' },
  { 'min_version' : '5.0.0',      'fixed_version': '5.1.2.42' }
];

# Require paranoia due to the VPN headend requiring a configuration we cannot check from the client
vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  require_paranoia:TRUE,
  severity:SECURITY_HOLE
);
