#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192656);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-0446",
    "CVE-2024-23120",
    "CVE-2024-23121",
    "CVE-2024-23122",
    "CVE-2024-23123",
    "CVE-2024-23124",
    "CVE-2024-23125",
    "CVE-2024-23126",
    "CVE-2024-23127",
    "CVE-2024-23128",
    "CVE-2024-23129",
    "CVE-2024-23130",
    "CVE-2024-23131",
    "CVE-2024-23132",
    "CVE-2024-23133",
    "CVE-2024-23134",
    "CVE-2024-23135",
    "CVE-2024-23136",
    "CVE-2024-23137",
    "CVE-2024-23138"
  );
  script_xref(name:"IAVA", value:"2024-A-0325-S");
  script_xref(name:"IAVA", value:"2024-A-0176-S");
  script_xref(name:"IAVA", value:"2024-A-0698-S");

  script_name(english:"Autodesk Multiple Vulnerabilities (AutoCAD) (adsk-sa-2024-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is a version prior to 2024.1.3, 2023.1.5,
2022.1.4 or 2021.1.4. It is, therefore, affected by multiple vulnerabilities:

  -  A maliciously crafted STP, CATPART or MODEL file in ASMKERN228A.dll when parsed through Autodesk AutoCAD can force
    an Out-of-Bound Write. A malicious actor can leverage this vulnerability to cause a crash, write sensitive data, 
    or execute arbitrary code in the context of the current process. (CVE-2024-0446)

  - A maliciously crafted STP file in ASMIMPORT228A.dll when parsed through Autodesk AutoCAD can force an Out-of-Bound 
    Write. A malicious actor can leverage this vulnerability to cause a crash, write sensitive data, or execute 
    arbitrary code in the context of the current process. (CVE-2024-23120)

  - A maliciously crafted MODEL file in libodxdll.dll when parsed through Autodesk AutoCAD can force an Out-of-Bound 
    Write. A malicious actor can leverage this vulnerability to cause a crash, write sensitive data, or execute 
    arbitrary code in the context of the current process. (CVE-2024-23121)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0004");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk AutoCAD versions 2024.1.3, 2023.1.5, 2022.1.4 or 2021.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0446");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-23138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Autodesk AutoCAD");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk AutoCAD', win_local:TRUE);

var constraints = [
  { 'min_version': '24.0', 'fixed_version' : '24.0.182.0' },  # 2021.1.4
  { 'min_version': '24.1', 'fixed_version' : '24.1.182.0' },  # 2022.1.4
  { 'min_version': '24.2', 'fixed_version' : '24.2.192.0' },  # 2023.1.5
  { 'min_version': '24.3', 'fixed_version' : '24.3.171.0' }   # 2024.1.3
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
