#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200465);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2024-0089",
    "CVE-2024-0090",
    "CVE-2024-0091",
    "CVE-2024-0092"
  );
  script_xref(name:"IAVA", value:"2024-A-0332");

  script_name(english:"NVIDIA Windows GPU Display Driver (June 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability where the information from a previous
    client or another process could be disclosed. A successful exploit of this vulnerability might lead to 
    code execution, information disclosure, or data tampering. (CVE-2024-0089)

  -	NVIDIA GPU driver for Windows and Linux contains a vulnerability where a user can cause an out-of-bounds
    write. A successful exploit of this vulnerability might lead to code execution, denial of service,
    escalation of privileges, information disclosure, and data tampering.(CVE-2024-0090)

  -	NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where a user can cause an 
    untrusted pointer dereference by executing a driver API. A successful exploit of this vulnerability might
    lead to denial of service, information disclosure, and data tampering. (CVE-2024-0091)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5551");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
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

var constraints = [
  {'min_version': '470', 'fixed_version': '475.06', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']},
  {'min_version': '535', 'fixed_version': '538.67', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla']},
  {'min_version': '550', 'fixed_version': '552.55', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla']},
  {'min_version': '555', 'fixed_version': '555.99', 'gpumodel':['nvs', 'quadro', 'rtx', 'geforce', 'studio']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
