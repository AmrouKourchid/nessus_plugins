#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209289);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-7993");
  script_xref(name:"IAVA", value:"2024-A-0678-S");

  script_name(english:"Autodesk Revit 2024.x < 2024.2.2 / 2025.x < 2025.3 PDF File Parsing Out-of-Bounds Write (ADSK-SA-2024-0018)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an out-of-bounds write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Autodesk Revit installed on the remote Windows host is 2024.x prior to 2024.2.2 or 2025.x prior to
2025.3. It is, therefore, affected by an out-of-bounds write vulnerability:

  - A maliciously crafted PDF file, when parsed through Autodesk Revit, can force an Out-of-Bounds Write. A malicious
    actor can leverage this vulnerability to cause a crash, write sensitive data, or execute arbitrary code in the
    context of the current process. (CVE-2024-7993)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2024-0018");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Autodesk Revit 2024.2.2 or 2025.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7993");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:revit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_revit_win_installed.nbin");
  script_require_keys("installed_sw/Autodesk Revit", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Autodesk Revit', win_local:TRUE);

var constraints = [
  {'min_version':'24.0.0.0', 'fixed_version':'24.2.2.0', 'fixed_display':'24.2.2.0 (2024.2.2)'}, 
  {'min_version':'25.0.0.0', 'fixed_version':'25.3.0.0', 'fixed_display':'25.3.0.0 (2025.3)'} 
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
