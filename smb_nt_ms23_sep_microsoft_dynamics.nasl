#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181340);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id(
    "CVE-2023-36433",
    "CVE-2023-36800",
    "CVE-2023-36886",
    "CVE-2023-38164"
  );
  script_xref(name:"MSKB", value:"5029396");
  script_xref(name:"MSKB", value:"5030608");
  script_xref(name:"MSFT", value:"MS23-5029396");
  script_xref(name:"MSFT", value:"MS23-5030608");
  script_xref(name:"IAVA", value:"2023-A-0483-S");
  script_xref(name:"IAVA", value:"2023-A-0544-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by 
multiple Cross-site Scripting vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5029396");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5030608");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB 5029396
  -KB 5030608");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.49.04', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.49' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.21.05', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.21' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags: {'xss': TRUE}
);
