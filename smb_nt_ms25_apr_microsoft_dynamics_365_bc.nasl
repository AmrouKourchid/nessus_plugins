#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234222);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-29821");
  script_xref(name:"MSKB", value:"5056718");
  script_xref(name:"MSKB", value:"5056716");
  script_xref(name:"MSKB", value:"5056717");
  script_xref(name:"MSFT", value:"MS24-5056718");
  script_xref(name:"MSFT", value:"MS24-5056716");
  script_xref(name:"MSFT", value:"MS24-5056717");
  script_xref(name:"IAVA", value:"2025-A-0248");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing security updates. It is, therefore, affected by a
information disclosure vulnerability. Improper input validation in Dynamics Business Central allows an authorized 
attacker to disclose information locally.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/5056718");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/5056716");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/5056717");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to 2023 Wave 2 – Update 23.18, 2024 Wave 1 – Update 24.12, 
2024 Wave 2 – Update 25.6, 2025 Wave 1 – Update 26.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29821");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '23.0', 'fixed_version' : '23.18.32409.0', 'fixed_display' : 'Update 23.18 for Microsoft Dynamics 365 Business Central 2023 Release Wave 2' },
  { 'min_version' : '24.0', 'fixed_version' : '24.12.32447.0', 'fixed_display' : 'Update 24.12 for Microsoft Dynamics 365 Business Central 2024 Release Wave 1' },
  { 'min_version' : '25.0', 'fixed_version' : '25.6.32556.0', 'fixed_display' : 'Update 25.6 for Microsoft Dynamics 365 Business Central 2024 Release Wave 2' },
  { 'min_version' : '26.0', 'fixed_version' : '26.0.32481.0', 'fixed_display' : 'Update 26.0 for Microsoft Dynamics 365 Business Central 2025 Release Wave 1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
