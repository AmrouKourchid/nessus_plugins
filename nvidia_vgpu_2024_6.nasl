#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200467);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-0084",
    "CVE-2024-0085",
    "CVE-2024-0086",
    "CVE-2024-0090",
    "CVE-2024-0091",
    "CVE-2024-0092",
    "CVE-2024-0093",
    "CVE-2024-0094",
    "CVE-2024-0099"
  );
  script_xref(name:"IAVA", value:"2024-A-0332");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  -	NVIDIA GPU driver for Windows and Linux contains a vulnerability where a user can cause an out-of-bounds
  write. A successful exploit of this vulnerability might lead to code execution, denial of service,
  escalation of privileges, information disclosure, and data tampering.(CVE-2024-0090)

  -	NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where a user can cause an 
  untrusted pointer dereference by executing a driver API. A successful exploit of this vulnerability might
  lead to denial of service, information disclosure, and data tampering. (CVE-2024-0091)

  - NVIDIA vGPU software for Linux contains a vulnerability in the Virtual GPU Manager, where the guest OS 
  could cause buffer overrun in the host. A successful exploit of this vulnerability might lead to
  information disclosure, data tampering, escalation of privileges, and denial of service. (CVE-2024-0099)
	
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5551");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA vGPU Manager software in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0091");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '470', 'fixed_version' : '470.256.02',   'fixed_display' : '13.11 (470.256.02)' },
  { 'min_version' : '535', 'fixed_version' : '535.183.04',   'fixed_display' : '16.6 (535.183.04)' },
  { 'min_version' : '550', 'fixed_version' : '550.90.05',    'fixed_display' : '17.2 (550.90.05)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
