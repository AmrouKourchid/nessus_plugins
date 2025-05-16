#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185433);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id(
    "CVE-2023-31016",
    "CVE-2023-31017",
    "CVE-2023-31019",
    "CVE-2023-31020",
    "CVE-2023-31022",
    "CVE-2023-31023",
    "CVE-2023-31027"
  );
  script_xref(name:"IAVA", value:"2023-A-0603-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability where an attacker may be able to write
    arbitrary data to privileged locations by using reparse points. A successful exploit of this vulnerability
    may lead to code execution, denial of service, escalation of privileges, information disclosure, or data
    tampering. (CVE-2023-31017)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in wksServicePlugin.dll, where the driver
    implementation does not restrict or incorrectly restricts access from the named pipe server to a
    connecting client, which may lead to potential impersonation to the client's secure context.
    (CVE-2023-31019)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability that allows Windows users with low levels
    of privilege to escalate privileges when an administrator is updating GPU drivers, which may lead to
    escalation of privileges. (CVE-2023-31027)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5491");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31016");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-31017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '470', 'fixed_version': '474.64', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']},
  {'min_version': '525', 'fixed_version': '529.19', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla']},
  {'min_version': '535', 'fixed_version': '537.70', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla']},
  {'min_version': '545', 'fixed_version': '546.01', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']},
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
