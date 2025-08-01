#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206154);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2024-7305");
  script_xref(name:"IAVA", value:"2024-A-0520-S");

  script_name(english:"Autodesk DWG TrueView 25.0.x < 25.0.101.0 (2025.1) (adsk-sa-2024-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk DWG TrueView installed on the remote host is prior to 25.0.101.0 (2025.1). It is, therefore,
affected by a vulnerability as referenced in the adsk-sa-2024-0014 advisory.

  - A maliciously crafted DWF file, when parsed in AdDwfPdk.dll through Autodesk AutoCAD, can force an Out-of-
    Bounds Write. A malicious actor can leverage this vulnerability to cause a crash, read sensitive data, or
    execute arbitrary code in the context of the current process. (CVE-2024-7305)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0014");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk DWG TrueView version 25.0.101.0 (2025.1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:dwg_trueview");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_dwg_trueview_installed.nbin");
  script_require_keys("installed_sw/Autodesk DWG TrueView");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk DWG TrueView', win_local:TRUE);

var constraints = [
  { 'min_version' : '25.0', 'fixed_version' : '25.0.101.0', 'fixed_display' : '25.0.101.0 (2025.1)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
