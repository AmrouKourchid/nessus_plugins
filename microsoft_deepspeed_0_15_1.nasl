#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208297);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-43497");

  script_name(english:"DeepSpeed < 0.15.1 Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a DeepSpeedserve version that is prior to  0.15.1. It is,
therefore, affected by an arbitrary code execution vulnerability. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/microsoft/DeepSpeed/releases/tag/v0.15.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69a86745");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-43497
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c55bb231");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DeepSpeed 0.15.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43497");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:deepspeed");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_deepspeed_detect.nasl");
  script_require_keys("installed_sw/DeepSpeed");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'DeepSpeed');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '0.15.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);