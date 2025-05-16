#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191744);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2022-42265",
    "CVE-2024-0074",
    "CVE-2024-0075",
    "CVE-2024-0078"
  );
  script_xref(name:"IAVA", value:"2024-A-0130-S");

  script_name(english:"NVIDIA Linux GPU Display Driver (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for WIndows and Linux contains a vulnerability in the kernel mode data handler, where an
    unprivileged regular user can cause integer overflow, which may lead to denial of service, information disclosure,
    and data tampering. (CVE-2022-42665)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability where an attacker may access a memory location after 
    the end of the buffer. A successful exploit of this vulnerability may lead to denial of service and data tampering. 
    (CVE-2024-0074)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where a user may cause a NULL-pointer 
    dereference by accessing passed parameters the validity of which has not been checked. A successful exploit of 
    this vulnerability may lead to denial of service and limited information disclosure. (CVE-2024-0075)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a user in 
    a guest can cause a NULL-pointer dereference in the host, which may lead to denial of service. (CVE-2024-0078)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5520
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20b94e14");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

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
  {'min_version':'470', 'fixed_version':'470.239.06', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'535', 'fixed_version':'535.161.07', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'550', 'fixed_version':'550.54.14',  'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
