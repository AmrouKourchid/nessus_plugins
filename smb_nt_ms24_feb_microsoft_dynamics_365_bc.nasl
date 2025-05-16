#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190546);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-21380");
  script_xref(name:"MSKB", value:"5035207");
  script_xref(name:"MSFT", value:"MS24-5029765");
  script_xref(name:"IAVA", value:"2024-A-0098-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by an
information disclosure vulnerability. A remote, authenticated attacker, by inducing another user to access a
compromised URL and winning a race condition, can to read, modify and delete sensitive user data.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5035205");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5035206");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5035207");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21380");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to 21.16 for 2022 Release Wave 2, 22.10 for 2023 Release Wave 1, 23.4 for 2023 Release Wave 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '21.0', 'fixed_version' : '21.0.63175.0', 'fixed_display' : 'Update 21.16 for Microsoft Dynamics 365 Business Central 2022 Release Wave 2' },
  { 'min_version' : '22.0', 'fixed_version' : '22.0.63124.0', 'fixed_display' : 'Update 22.10 for Microsoft Dynamics 365 Business Central 2023 Release Wave 1' },
  { 'min_version' : '23.0', 'fixed_version' : '23.0.15712.0', 'fixed_display' : 'Update 23.4 for Microsoft Dynamics 365 Business Central 2023 Release Wave 2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
