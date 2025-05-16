#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204786);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2024-6096");
  script_xref(name:"IAVB", value:"2024-B-0100-S");

  script_name(english:"Progress Telerik Reporting < 2024 Q2 (18.1.24.709) Object Injection");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by object injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Progress Telerik Reporting installed on the remote Windows host is prior to 2024 Q2 (18.1.24.709). It
is, therefore, affected by an object injection vulnerability:

  - In Progress® Telerik® Reporting versions prior to 18.1.24.709, an object injection attack is possible through an 
    insecure type resolution vulnerability. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.telerik.com/reporting/knowledge-base/unsafe-reflection-cve-2024-6096
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc9e123c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress Telerik Reporting 2024 Q2 (18.1.24.709) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6096");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:telerik_reporting");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_telerik_reporting_win_installed.nbin");
  script_require_keys("installed_sw/Progress Telerik Reporting", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress Telerik Reporting', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '18.1.24.709' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
