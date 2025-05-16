#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180574);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/30");

  script_cve_id(
    "CVE-2023-29073",
    "CVE-2023-29074",
    "CVE-2023-29075",
    "CVE-2023-29076",
    "CVE-2023-41139",
    "CVE-2023-41140"
  );
  script_xref(name:"IAVA", value:"2023-A-0454");

  script_name(english:"Autodesk Multiple Vulnerabilities (AutoCAD) (adsk-sa-2023-0018)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is a version prior to 2023.1.4. 
It is, therefore, affected by multiple vulnerabilities.

  -  A maliciously crafted MODEL file when parsed through Autodesk AutoCAD 2023 can be used to cause a Heap-Based 
    Buffer Overflow. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or 
    execute arbitrary code in the context of the current process. (CVE-2023-29073)

  - A maliciously crafted CATPART file when parsed through Autodesk AutoCAD 2023 can be used to cause an Out-Of-Bounds 
    Write. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute 
    arbitrary code in the context of the current process. (CVE-2023-29074) 

  - A maliciously crafted PRT file when parsed through Autodesk AutoCAD 2023 can be used to cause an Out-Of-Bounds 
    Write. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or execute 
    arbitrary code in the context of the current process. (CVE-2023-29075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2023-0018");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk AutoCAD version 2023.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Autodesk AutoCAD");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk AutoCAD', win_local:TRUE);

# https://www.autodesk.com/support/technical/article/caas/sfdcarticles/sfdcarticles/How-to-tie-the-Product-Version-or-Build-number-with-the-AutoCAD-update.html
# https://help.autodesk.com/view/ACD/2023/ENU/?guid=AUTOCAD_2023_UPDATES
var constraints = [
  { 'min_version': '24.2', 'fixed_version' : '24.2.181.0' }  # 2023.1.4
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);