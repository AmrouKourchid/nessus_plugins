#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179633);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2023-38170");

  script_name(english:"Microsoft Windows HEVC Video Extensions RCE (August 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows 'HEVC Video Extensions' app installed on the remote host is affected by
a remote code execution vulnerability. An attacker who successfully exploits this vulnerability could execute
arbitrary code. Exploitation of the vulnerability requires that a program process a specially crafted file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-38170
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ade0bfbf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 2.0.61933.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:hevc_video_extensions");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

#  Microsoft.HEVCVideoExtensions - app installed by user from MS Store
var app = 'Microsoft.HEVCVideoExtensions';

var app_info = vcf::microsoft_appstore::get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '2.0.61933.0'}
];

vcf::microsoft_appstore::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
