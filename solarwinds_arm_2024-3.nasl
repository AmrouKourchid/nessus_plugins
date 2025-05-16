#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202717);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id(
    "CVE-2024-23465",
    "CVE-2024-23466",
    "CVE-2024-23467",
    "CVE-2024-23468",
    "CVE-2024-23469",
    "CVE-2024-23470",
    "CVE-2024-23471",
    "CVE-2024-23472",
    "CVE-2024-23474",
    "CVE-2024-23475",
    "CVE-2024-28074",
    "CVE-2024-28992",
    "CVE-2024-28993"
  );
  script_xref(name:"IAVB", value:"2024-B-0094-S");

  script_name(english:"SolarWinds ARM < 24.3 (arm_2024_3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds ARM installed on the remote host is prior to 24.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the arm_2024-3 advisory, including the following:

  - The SolarWinds Access Rights Manager was found to be susceptible to a Remote Code 
    Execution Vulnerability. If exploited, this vulnerability allows an authenticated 
    user to abuse a SolarWinds service resulting in remote code execution. (CVE-2024-23471)

  - The SolarWinds Access Rights Manager was susceptible to a Directory Traversal and 
    Information Disclosure Vulnerability. This vulnerability allows an unauthenticated 
    user to perform arbitrary file deletion and leak sensitive information. (CVE-2024-23475)

  - SolarWinds Access Rights Manager (ARM) is susceptible to a Remote Code Execution 
    vulnerability. If exploited, this vulnerability allows an unauthenticated user to 
    perform the actions with SYSTEM privileges. (CVE-2024-23469)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/arm/content/release_notes/arm_2024-3_release_notes.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8623e9d");
  script_set_attribute(attribute:"solution", value:
"Upgrade SolarWinds ARM based upon the guidance specified in 2024-3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28074");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:access_rights_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_arm_win_installed.nbin");
  script_require_keys("installed_sw/SolarWinds ARM", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'SolarWinds ARM', win_local:TRUE);

var constraints = [ { 'fixed_version' : '24.3' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);