#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235060);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-23244");
  script_xref(name:"IAVA", value:"2025-A-0309");

  script_name(english:"NVIDIA Linux GPU Display Driver (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Linux host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Linux host is affected by a vulnerability:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability which could allow an unprivileged attacker 
    to escalate permissions. A successful exploit of this vulnerability might lead to code execution, denial 
    of service, escalation of privileges, information disclosure, and data tampering. (CVE-2025-23244)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5630/~/security-bulletin%3A-nvidia-gpu-display-driver---april-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eef0d64c");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23244");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();
  
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '535', 'fixed_version': '535.247.01', 'gpumodel':['rtx', 'quadro', 'nvs', 'tesla', 'geforce']},
  {'min_version': '550', 'fixed_version': '550.163.01', 'gpumodel':['rtx', 'quadro', 'nvs', 'tesla', 'geforce']},
  {'min_version': '570', 'fixed_version': '570.133.07', 'gpumodel':['rtx', 'quadro', 'nvs', 'geforce']},
  {'min_version': '570', 'fixed_version': '570.133.20', 'gpumodel':['tesla']},
  {'min_version': '575', 'fixed_version': '575.51.02', 'gpumodel':['rtx', 'quadro', 'nvs', 'geforce']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
