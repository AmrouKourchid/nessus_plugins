#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200466);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2024-0090", "CVE-2024-0091", "CVE-2024-0092");
  script_xref(name:"IAVA", value:"2024-A-0332");

  script_name(english:"NVIDIA Linux GPU Display Driver (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, 
affected by multiple vulnerabilities, including the following:

  -	NVIDIA GPU driver for Windows and Linux contains a vulnerability where a user can cause an out-of-bounds
  write. A successful exploit of this vulnerability might lead to code execution, denial of service,
  escalation of privileges, information disclosure, and data tampering.(CVE-2024-0090)

  -	NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where a user can cause an 
  untrusted pointer dereference by executing a driver API. A successful exploit of this vulnerability might
  lead to denial of service, information disclosure, and data tampering. (CVE-2024-0091)

  - NVIDIA GPU Driver for Windows and Linux contains a vulnerability where an improper check or improper
  handling of exception conditions might lead to denial of service. (CVE-2024-0092)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5551");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
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

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'470', 'fixed_version':'470.256.02', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'535', 'fixed_version':'535.183.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'550', 'fixed_version':'550.90.07',  'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'555', 'fixed_version':'555.52.04',  'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
