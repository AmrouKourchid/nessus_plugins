#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185434);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id(
    "CVE-2023-31016",
    "CVE-2023-31017",
    "CVE-2023-31018",
    "CVE-2023-31019",
    "CVE-2023-31020",
    "CVE-2023-31021",
    "CVE-2023-31022",
    "CVE-2023-31023",
    "CVE-2023-31026",
    "CVE-2023-31027"
  );
  script_xref(name:"IAVA", value:"2023-A-0603-S");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (October 2023)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA GPU Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where an unprivileged 
    regular user can cause a NULL-pointer dereference, which may lead to denial of service. (CVE‑2023‑31018)

  - NVIDIA vGPU software for Windows and Linux contains a vulnerability in the Virtual GPU Manager (vGPU plugin), 
    where a malicious user in the guest VM can cause a NULL-pointer dereference, which may lead to denial of service. 
    (CVE‑2023‑31021)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability that allows Windows users with low levels of 
    privilege to escalate privileges when an administrator is updating GPU drivers, which may lead to escalation of 
    privileges. (CVE-2023-31027)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5491
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da28f73d");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA vGPU Manager software in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31016");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-31017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '470', 'fixed_version' : '470.223.02',   'fixed_display' : '13.9 (470.223.02)' },
  { 'min_version' : '525', 'fixed_version' : '525.147.01',   'fixed_display' : '15.4 (525.147.01)' },
  { 'min_version' : '535', 'fixed_version' : '535.109.03',   'fixed_display' : '16.2 (535.109.03)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
