#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209661);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2024-43468");
  script_xref(name:"MSKB", value:"29166583");
  script_xref(name:"MSFT", value:"MS22-29166583");
  script_xref(name:"IAVA", value:"2024-A-0645");

  script_name(english:"Microsoft Endpoint Configuration Manager RCE (KB29166583)");

  script_set_attribute(attribute:"synopsis", value:
"A system management application installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Endpoint Configuration Manager application installed on the remote host is missing a security hotfix
documented in KB29166583. It is, therefore, affected by a remote code execution vulnerability. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/mem/configmgr/hotfix/2403/29166583
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48fcb2d1");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-43468
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bce56e4a");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch according to KB29166583.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:endpoint_configuration_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_systems_management_server_installed.nasl", "microsoft_configuration_manager_win_installed.nbin");
  script_require_ports("installed_sw/Microsoft Endpoint Configuration Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Endpoint Configuration Manager', win_local:TRUE);

# check platform, fix is for 64 bit
var kb_arch = get_kb_item("SMB/ARCH");
var update_ver = app_info.update;
var constraints = [];

if(!empty_or_null(kb_arch) && "x64" >!< kb_arch)
  audit(AUDIT_HOST_NOT, "x64"); 

# check product update package 
if(empty_or_null(update_ver))
   audit(AUDIT_HOST_NOT, "affected"); 

if(update_ver == '2403')
  constraints = [{'fixed_version': '5.0.9128.1024', 'fixed_display': 'See vendor advisory'}];
else if (update_ver == '2309')
  constraints = [{'fixed_version': '5.0.9122.1033', 'fixed_display': 'See vendor advisory'}];
else if (update_ver == '2303')
  constraints = [{'fixed_version': '5.0.9106.1037', 'fixed_display': 'See vendor advisory'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
