#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216750);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2025-21322");

  script_name(english:"Microsoft PC Manager Elevation of Privilege (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows 'Microsoft PC Manager' app installed on the remote host is affected by
an elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21322
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c809fbfe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 3.15.4.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:microsoft_pc_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Microsoft.MicrosoftPCManager';

var app_info = vcf::microsoft_appstore::get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '3.15.4.0'}
];

vcf::microsoft_appstore::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
