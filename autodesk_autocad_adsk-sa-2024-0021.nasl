#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210051);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-7991",
    "CVE-2024-7992",
    "CVE-2024-8587",
    "CVE-2024-8588",
    "CVE-2024-8589",
    "CVE-2024-8590",
    "CVE-2024-8591",
    "CVE-2024-8593",
    "CVE-2024-8594",
    "CVE-2024-8595",
    "CVE-2024-8596",
    "CVE-2024-8597",
    "CVE-2024-8598",
    "CVE-2024-8599",
    "CVE-2024-8600",
    "CVE-2024-8896",
    "CVE-2024-9489",
    "CVE-2024-9826",
    "CVE-2024-9827",
    "CVE-2024-9996",
    "CVE-2024-9997"
  );
  script_xref(name:"IAVA", value:"2024-A-0698-S");

  script_name(english:"Autodesk Multiple Vulnerabilities (AutoCAD) (adsk-sa-2024-0019) (adsk-sa-2024-0021)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk AutoCAD installed on the remote Windows host is a version prior to 2025.1.1. It is, 
therefore, affected by multiple vulnerabilities:

  - A maliciously crafted SLDPRT file when parsed in odxsw_dll.dll through Autodesk affected applications can force a
    Heap-Based Buffer Overflow vulnerability. A malicious actor can leverage this vulnerability to cause a crash,
    write sensitive data, or execute arbitrary code in the context of the current process. (CVE-2024-8587)

  - A maliciously crafted SLDPRT file when parsed in odxsw_dll.dll through Autodesk affected applications can force
    an Out-of-Bounds Read vulnerability. A malicious actor can leverage this vulnerability to cause a crash, write
    sensitive data, or execute arbitrary code in the context of the current process. (CVE-2024-8588)

  - A maliciously crafted SLDPRT file when parsed in odxsw_dll.dll through Autodesk affected applications can force an
    Out-of-Bounds Read vulnerability. A malicious actor can leverage this vulnerability to cause a crash, write 
    sensitive data, or execute arbitrary code in the context of the current process. (CVE-2024-8589)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0019");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0021");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk AutoCAD versions 2025.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9997");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:autocad");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autocad_installed.nbin");
  script_require_keys("installed_sw/Autodesk AutoCAD");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Autodesk AutoCAD', win_local:TRUE);

var constraints = [
  { 'min_version': '25.0.058.0', 'fixed_version' : '25.0.154.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
