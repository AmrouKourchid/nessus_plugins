#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190889);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2023-40057",
    "CVE-2024-23476",
    "CVE-2024-23477",
    "CVE-2024-23478",
    "CVE-2024-23479"
  );
  script_xref(name:"IAVB", value:"2024-B-0015-S");

  script_name(english:"SolarWinds ARM < 2023.2.3 Multiple Vulnerabilities (arm_2023-2-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds ARM installed on the remote host is prior to 2023.2.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the arm_2023-2-3 advisory.

  - The SolarWinds Access Rights Manager was found to be susceptible to a Remote Code Execution Vulnerability.
    If exploited, this vulnerability allows an authenticated user to abuse a SolarWinds service resulting in
    remote code execution. (CVE-2023-40057)

  - The SolarWinds Access Rights Manager (ARM) was found to be susceptible to a Directory Traversal Remote
    Code Execution Vulnerability. If exploited, this vulnerability allows an unauthenticated user to achieve
    the Remote Code Execution. (CVE-2024-23476)

  - The SolarWinds Access Rights Manager (ARM) was found to be susceptible to a Directory Traversal Remote
    Code Execution Vulnerability. If exploited, this vulnerability allows an unauthenticated user to achieve a
    Remote Code Execution. (CVE-2024-23477)

  - SolarWinds Access Rights Manager (ARM) was found to be susceptible to a Remote Code Execution
    Vulnerability. If exploited, this vulnerability allows an authenticated user to abuse a SolarWinds
    service, resulting in remote code execution. (CVE-2024-23478)

  - SolarWinds Access Rights Manager (ARM) was found to be susceptible to a Directory Traversal Remote Code
    Execution Vulnerability. If exploited, this vulnerability allows an unauthenticated user to achieve a
    Remote Code Execution. (CVE-2024-23479)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade SolarWinds ARM based upon the guidance specified in arm_2023-2-3.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

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

var constraints = [
  { 'fixed_version' : '23.2.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
