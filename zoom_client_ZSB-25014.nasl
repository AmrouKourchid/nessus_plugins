#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234236);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-27443");
  script_xref(name:"IAVA", value:"2025-A-0228");

  script_name(english:"Zoom Client for Meetings < 6.3.10 Insecure Default Variable Initialization Vulnerability (ZSB-25014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a Insecure Default Variable Initialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is prior to 6.3.10. It is, therefore, affected by
a vulnerability as referenced in the ZSB-25014 advisory.
  
- Insecure default variable initialization in some Zoom Workplace Apps for Windows may allow an authenticated user to 
  conduct a loss of integrity via local access. (CVE-2025-27443)
  
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zoom.com/en/trust/security-bulletin/ZSB-25014");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 6.3.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27443");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);


vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '6.3.10' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);