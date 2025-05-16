#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235061);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-23245", "CVE-2025-23246");
  script_xref(name:"IAVA", value:"2025-A-0309");

  script_name(english:"NVIDIA Virtual GPU Manager DoS (CVE-2025-23245) (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
denial of service vulnerability:

  -	NVIDIA vGPU software for Windows and Linux contains a vulnerability in the Virtual GPU Manager 
    (vGPU plugin), where it allows a guest to access global resources. A successful exploit of this 
    vulnerability might lead to denial of service. (CVE-2025-23245)

  -	NVIDIA vGPU software for Windows and Linux contains a vulnerability in the Virtual GPU Manager 
    (vGPU plugin), where it allows a guest to consume uncontrolled resources. A successful exploit of this 
    vulnerability might lead to denial of service. (CVE-2025-23246)
	
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5551");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA vGPU Manager software in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23245");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '535', 'fixed_version' : '535.247.02', 'fixed_display' : '16.10 (535.247.02)' },
  { 'min_version' : '550', 'fixed_version' : '550.163.02', 'fixed_display' : '17.6 (550.163.02)' },
  { 'min_version' : '570', 'fixed_version' : '570.133.10', 'fixed_display' : '18.1 (570.133.10)' },
  { 'min_version' : '572', 'fixed_version' : '572.83', 'fixed_display' : '18.1 (572.83)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
