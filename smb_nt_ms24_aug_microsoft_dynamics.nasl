#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205531);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-38211");
  script_xref(name:"MSKB", value:"5041557");
  script_xref(name:"MSFT", value:"MS24-5041557");
  script_xref(name:"IAVA", value:"2024-A-0488-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by an Cross Side Scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by an cross-site 
scripting vulnerability. An attacker can exploit this to disclose potentially sensitive information and potenital 
hijack a user session.

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.microsoft.com/en-us/topic/service-update-1-31-for-microsoft-dynamics-crm-on-premises-9-1-a1c7392c-4073-4201-b558-d3f806d87370
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca11d158");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?819d54ec");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5041557");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.1', 'fixed_version' : '9.1.31.10', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.31' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags: {'xss': TRUE}
);
