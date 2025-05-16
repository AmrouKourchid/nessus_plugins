#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179137);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/02");

  script_cve_id("CVE-2023-24491");

  script_name(english:"Citrix Secure Access < 23.5.1.3 Privilege Escalation (CTX561480)");

  script_set_attribute(attribute:"synopsis", value:
"Citrix Secure Access formerly known as Citrix Gateway Plug-in for Windows installed on the remote Windows 
host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A privilege escalation vulnerability has been discovered in the Citrix Secure Access client for Windows which, if exploited, could allow an 
attacker with access to an endpoint with Standard User Account that has the vulnerable client installed to escalate 
their local privileges to that of NT AUTHORITY\SYSTEM.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.citrix.com/article/CTX561480/citrix-secure-access-client-for-windows-security-bulletin-for-cve202324491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ab65425");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Gateway Plug-in for Windows version 23.5.1.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:gateway_plug-in");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:secure_access");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_gateway_plug-in_detect.nbin");
  script_require_ports("installed_sw/Citrix Gateway Plug-in", "installed_sw/Citrix Secure Access", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Citrix Secure Access', win_local:TRUE);

var constraints = [ { 'fixed_version' : '23.5.1.3'} ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
