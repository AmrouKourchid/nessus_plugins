#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191676);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2024-0071",
    "CVE-2024-0073",
    "CVE-2024-0075",
    "CVE-2024-0078",
    "CVE-2022-42265"
  );
  script_xref(name:"IAVA", value:"2024-A-0130-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the user mode layer, where an 
    unprivileged regular user can cause an out-of-bounds write. A successful exploit of this vulnerability may
    lead to code execution, denial of service, escalation of privileges, information disclosure, and data 
    tampering. (CVE-2024-0071)

  -	NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer when the driver is
    performing an operation at a privilege level that is higher than the minimum level required. A successful
    exploit of this vulnerability may lead to code execution, denial of service, escalation of privileges,
    information disclosure, and data tampering. (CVE-2024-0073)

  -	NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a
    user in a guest can cause a NULL-pointer dereference in the host, which may lead to denial of service.
    (CVE-2024-0078)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5520");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0071");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var R470_fixed = '474.82';
var win_ver = get_kb_item_or_exit('SMB/WindowsVersion');
# Win 7x & 8x
if (win_ver == '6.1' || win_ver == '6.2' || win_ver == '6.3')
  R470_fixed = '474.89';

var constraints = [
  {'min_version': '470', 'fixed_version': R470_fixed, 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']},
  {'min_version': '535', 'fixed_version': '538.33', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla']},
  {'min_version': '550', 'fixed_version': '551.61', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
