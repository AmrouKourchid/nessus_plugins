#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197511);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2024-28075");
  script_xref(name:"IAVB", value:"2024-B-0059-S");

  script_name(english:"SolarWinds ARM < 23.2.4 (arm_2023-2-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds ARM installed on the remote host is prior to 23.2.4. It is, therefore, affected by a
vulnerability as referenced in the arm_2023-2-4 advisory.

  - The SolarWinds Access Rights Manager was susceptible to Remote Code Execution Vulnerability. This
    vulnerability allows an authenticated user to abuse SolarWinds service resulting in remote code execution.
    We thank Trend Micro Zero Day Initiative (ZDI) for its ongoing partnership in coordinating with SolarWinds
    on responsible disclosure of this and other potential vulnerabilities. (CVE-2024-28075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2024-28075
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9b44198");
  script_set_attribute(attribute:"solution", value:
"Upgrade SolarWinds ARM based upon the guidance specified in 2023-2-4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28075");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:access_rights_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_arm_win_installed.nbin");
  script_require_keys("installed_sw/SolarWinds ARM", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SolarWinds ARM', win_local:TRUE);

var constraints = [ { 'fixed_version' : '23.2.4' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);