#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179836);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/15");

  script_cve_id("CVE-2023-38167");
  script_xref(name:"MSKB", value:"5029765");
  script_xref(name:"MSFT", value:"MS22-5029765");
  script_xref(name:"IAVA", value:"2023-A-0407-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by an
escalation of privilege vulnerability. This vulnerability requires that the attacker already has high privileges
to a security group on the tenet.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38167");
  # https://support.microsoft.com/en-us/topic/update-22-4-for-microsoft-dynamics-365-business-central-on-premises-2023-release-wave-1-application-build-22-4-59535-platform-build-22-0-59520-ba925fdc-d98e-4816-8abc-e5dde1ff0f34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4791af2");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to 22.4 for 2023 Release Wave 1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Business Central Server';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '22.0', 'fixed_version' : '22.0.59520.0', 'fixed_display' : 'Update 22.4 for Microsoft Dynamics 365 Business Central 2023 Release Wave 1' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
