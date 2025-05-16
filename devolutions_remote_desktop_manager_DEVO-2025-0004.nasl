#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233178);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-1635", "CVE-2025-1636");
  script_xref(name:"IAVB", value:"2025-B-0040-S");

  script_name(english:"Devolutions Remote Desktop Manager <= 2024.3.29 Multiple Vulnerabilities (DEVO-2025-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Remote Desktop Manager instance installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Devolutions Remote Desktop Manager installed on the remote host is prior or equal to 2024.3.29 and is,
therefore, affected by multiple vulnerabilities:

  - Exposure of sensitive information in hub data source export feature in Devolutions Remote Desktop Manager 2024.3.29
    and earlier on Windows allows a user exporting a hub data source to include his authenticated session in the export
    due to faulty business logic. (CVE-2025-1635)

  - Exposure of sensitive information in My Personal Credentials password history component in Devolutions Remote
    Desktop Manager 2024.3.29 and earlier on Windows allows an authenticated user to inadvertently leak the My Personal
    Credentials in a shared vault via the clear history feature due to faulty business logic. (CVE-2025-1636)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2025-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Remote Desktop Manager version 2025.1.24 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1635");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_desktop_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_desktop_manager_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Remote Desktop Manager", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Devolutions Remote Desktop Manager', win_local:TRUE);

var constraints = [
  { 'max_version':'2024.3.29', 'fixed_version':'2025.1.24' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
