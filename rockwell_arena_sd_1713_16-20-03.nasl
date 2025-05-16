#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212708);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-11156", "CVE-2024-12130");
  script_xref(name:"IAVB", value:"2024-B-0195-S");

  script_name(english:"Rockwell Automation Arena < 16.20.03 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An updater application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Rockwell Automation Arena installed on the remote Windows host is prior to 
16.20.06. It is, therefore, affected by a number of different vulnerabilities

  - An “out of bounds write”  code execution vulnerability exists in the affected products that could allow a 
    threat actor to write beyond the boundaries of allocated memory in a DOE file. If exploited, a threat actor 
    could leverage this vulnerability to execute arbitrary code. To exploit this vulnerability, a legitimate user must 
    execute the malicious code crafted by the threat actor. (CVE-2024-11156)

  - An “out of bounds read” code execution vulnerability exists in the affected products that could allow a threat 
    actor to craft a DOE file and force the software to read beyond the boundaries of an allocated memory. 
    If exploited, a threat actor could leverage this vulnerability to execute arbitrary code. To exploit this 
    vulnerability, a legitimate user must execute the malicious code crafted by the threat actor. (CVE-2024-12130)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.rockwellautomation.com/en-us/trust-center/security-advisories/advisory.SD1713.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f3fe95d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Rockwell Automation Arena 16.20.06 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12130");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rockwellautomation:arena");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rockwell_arena_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Rockwell Arena");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Rockwell Arena', win_local:TRUE);

var constraints = [
  { 'max_version':'16.20.03', 'fixed_version' : '16.20.06' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
