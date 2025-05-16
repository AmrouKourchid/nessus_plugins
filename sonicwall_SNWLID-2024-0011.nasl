#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212133);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-29014");
  script_xref(name:"IAVB", value:"2024-B-0189-S");

  script_name(english:"SonicWall NetExtender Arbitrary Code Execution (SNWLID-2024-0011)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Sonicwall NetExtender client is vulnerable to a to arbitrary code execution 
when processing an EPC Client update. A remote attacker could use this vulnerability to execute code with the admin 
permissions on the host machine.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0011");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29014");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sonicwall:netextender");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_net_extender_win_installed.nbin");
  script_require_keys("installed_sw/SonicWall NetExtender");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SonicWall NetExtender', win_local:TRUE);

var constraints = [
  {'max_version': '10.2.339', 'fixed_version':'10.2.341'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints,
  severity:SECURITY_HOLE);
