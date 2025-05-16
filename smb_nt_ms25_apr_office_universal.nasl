#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235085);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-26687");

  script_name(english:"Microsoft Office for Universal Privilege Escalation (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office for Universal products are affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office for Universal products are missing a security update. It is, therefore, affected by a privilege
escalation vulnerability. Use after free in Windows Win32K - GRFX allows an unauthorized attacker to elevate privileges
over a network.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-26687");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 16.0.14326.22331 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26687");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf_extras.inc');

var apps = [
  'Microsoft.Office.Word',
  'Microsoft.Office.Excel',
  'Microsoft.Office.PowerPoint'
];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# added two check for 2 different version format
var constraints = [
    { 'min_version' : '16.0', 'fixed_version' : '16.0.14326.22331' },
    { 'min_version' : '16001.0', 'fixed_version' : '16001.14326.22331.0' }
];

vcf::microsoft_appstore::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
