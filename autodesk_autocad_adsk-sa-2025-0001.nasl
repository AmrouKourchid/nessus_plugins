#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{ 
  script_id(233189);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2025-1427",
    "CVE-2025-1428",
    "CVE-2025-1429",
    "CVE-2025-1430",
    "CVE-2025-1432",
    "CVE-2025-1433",
    "CVE-2025-1649",
    "CVE-2025-1650",
    "CVE-2025-1651"
  );
  script_xref(name:"IAVA", value:"2025-A-0184");

  script_name(english:"Autodesk 2025 < 2025.1.2 Multiple Vulnerabilities (AutoCAD) (adsk-sa-2025-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The 2025 version of Autodesk AutoCAD installed on the remote Windows host is a version prior to 2025.1.2. It is, 
therefore, affected by multiple vulnerabilities:

  - A maliciously crafted CATPRODUCT file, when parsed through Autodesk AutoCAD, can force an
    Uninitialized Variable vulnerability. A malicious actor can leverage this vulnerability to cause a crash, 
    read sensitive data, or execute arbitrary code in the context of the current process. (CVE-2025-1427)

  - A maliciously crafted CATPART file, when parsed through Autodesk AutoCAD, can force an Out-of-Bounds Read 
    vulnerability. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or 
    execute arbitrary code in the context of the current process. (CVE-2025-1428)

  - A maliciously crafted SLDPRT file, when parsed through Autodesk AutoCAD, can force a Memory Corruption 
    vulnerability. A malicious actor can leverage this vulnerability to execute arbitrary code in the context 
    of the current process. (CVE-2025-1430)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2025-0001");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk AutoCAD versions 2025.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1427");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1427");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("installed_sw/Autodesk AutoCAD");

  exit(0);
}
include('vdf.inc');
# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target', 'match': {'os': 'windows'}}],
  'checks': [
    {
      'product':{'name': 'Autodesk AutoCAD', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'min_version': '25.0', 'fixed_version': '25.0.162', 'fixed_display': '25.1.2'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
