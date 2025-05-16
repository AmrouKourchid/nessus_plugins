#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214527);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-0131", "CVE-2024-0147", "CVE-2024-0150");
  script_xref(name:"IAVA", value:"2025-A-0054");

  script_name(english:"NVIDIA Windows GPU Display Driver (January 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including:

  - NVIDIA GPU display driver for Windows and Linux contains a vulnerability where data is written past the end or
    before the beginning of a buffer. A successful exploit of this vulnerability might lead to information disclosure,
    denial of service, or data tampering. (CVE-2024-0150)

  - NVIDIA GPU display driver for Windows and Linux contains a vulnerability where referencing memory after it has been
    freed can lead to denial of service or data tampering. (CVE-2024-0147)

  - NVIDIA GPU kernel driver for Windows and Linux contains a vulnerability where a potential user-mode attacker could
    read a buffer with an incorrect length. A successful exploit of this vulnerability might lead to denial of service.
    (CVE-2024-0131)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5614/~/security-bulletin%3A-nvidia-gpu-display-driver---january-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fa55374");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '550', 'fixed_version': '553.62', 'gpumodel':['rtx', 'quadro', 'nvs', 'tesla']},
  {'min_version': '535', 'fixed_version': '539.19', 'gpumodel':['rtx', 'quadro', 'nvs', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
