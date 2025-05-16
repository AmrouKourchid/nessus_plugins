#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202033);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/10");

  script_cve_id("CVE-2024-30061");
  script_xref(name:"MSKB", value:"5037940");
  script_xref(name:"MSFT", value:"MS24-5037940");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by an information 
disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.microsoft.com/en-us/topic/e012db2f-5b80-4b5f-bc1e-618faf7f4c98
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d80ba2e");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb678c09");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5037940");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30061");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
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
  { 'min_version' : '9.1', 'fixed_version' : '9.1.28.09', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.28' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags: {'xss': TRUE}
);
