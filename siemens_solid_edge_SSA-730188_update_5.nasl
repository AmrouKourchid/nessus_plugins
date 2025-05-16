#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212771);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2024-54093", "CVE-2024-54094");
  script_xref(name:"IAVA", value:"2024-A-0815");

  script_name(english:"Siemens Solid Edge SSA-730188 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A CAD  application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Siemens Solid Edge installed on the remote Windows host is prior to 224.00.05.04. It is,
therefore, affected by multiple vulnerabilities. For more information, consult the vendor advisory.

- A vulnerability has been identified in Solid Edge SE2024 (All versions < V224.0 Update 5). The affected 
  application is vulnerable to heap-based buffer overflow while parsing specially crafted ASM files. This could allow 
  an attacker to execute code in the context of the current process. (CVE-2024-54093)

- A vulnerability has been identified in Solid Edge SE2024 (All versions < V224.0 Update 5). The affected 
  application is vulnerable to heap-based buffer overflow while parsing specially crafted PAR files. This could allow
  an attacker to execute code in the context of the current process. (CVE-2024-54094)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/html/ssa-351178.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Siemens Solid Edge 2024 Update 5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54094");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:chipset_device_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_solid_edge_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Solid Edge");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Solid Edge', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '224.0.5.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
