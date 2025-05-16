#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176519);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2023-25004", "CVE-2023-29068");
  script_xref(name:"IAVA", value:"2023-A-0258");

  script_name(english:"Autodesk PSKernel Out-of-bounds Read/Write (VRED) (adsk-sa-2023-0009)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk VRED installed on the remote Windows host is affected by an out-of-bounds read/write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk VRED installed on the remote Windows host is version 2023.x prior to 2023.4. It is, therefore,
affected by multiple vulnerabilities.

  - A maliciously crafted pskernel.dll file in Autodesk products is used to trigger integer overflow
  vulnerabilities. Exploitation of these vulnerabilities may lead to code execution. (CVE-2023-25004)
  
  - A maliciously crafted file consumed through pskernel.dll file could lead to memory corruption
  vulnerabilities. These vulnerabilities in conjunction with other vulnerabilities could lead to code
  execution in the context of the current process. (CVE-2023-29068)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2023-0009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk VRED 2023.4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:vred");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_vred_installed.nbin");
  script_require_keys("installed_sw/Autodesk VRED");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'Autodesk VRED', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version': '15.0', 'fixed_version': '15.4'}
      ]
    }
  ]
};

# Note: VRED 2023.0 is detected as 15.0 and 2023.4 as 15.4

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);