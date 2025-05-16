#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180174);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2023-38831", "CVE-2023-40477");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/09/14");
  script_xref(name:"IAVA", value:"2023-A-0436-S");

  script_name(english:"WinRAR < 6.23 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed which is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows.

  The version of WinRAR installed on the remote host is affected by a an improper validation of user-supplied 
  data, which can result in memory access past the end of an allocated buffer which can be exploited remotely 
  and may allow attackers to execute code in the context of the current process.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-23-1152/");
  script_set_attribute(attribute:"see_also", value:"https://www.rarlab.com/rarnew.htm");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinRAR version 6.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40477");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WinRAR CVE-2023-38831 Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rarlab:winrar");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'RARLAB WinRAR', win_local:TRUE);

var constraints = [ { 'fixed_version' : '6.23' } ];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
