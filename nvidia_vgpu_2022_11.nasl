#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181414);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id(
    "CVE-2022-34670",
    "CVE-2022-34674",
    "CVE-2022-34675",
    "CVE-2022-34676",
    "CVE-2022-34677",
    "CVE-2022-34678",
    "CVE-2022-34679",
    "CVE-2022-34680",
    "CVE-2022-34682",
    "CVE-2022-34684",
    "CVE-2022-42254",
    "CVE-2022-42255",
    "CVE-2022-42256",
    "CVE-2022-42257",
    "CVE-2022-42258",
    "CVE-2022-42259",
    "CVE-2022-42261",
    "CVE-2022-42262",
    "CVE-2022-42263",
    "CVE-2022-42264"
  );
  script_xref(name:"IAVA", value:"2022-A-0504-S");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause truncation errors when casting a primitive to a primitive of smaller
    size causes data to be lost in the conversion, which may lead to denial of service or information
    disclosure. (CVE-2022-34670)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an
    unprivileged regular user can cause the use of an out-of-range pointer offset, which may lead to data
    tampering, data loss, information disclosure, or denial of service. (CVE-2022-42264)

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where an input
    index is not validated, which may lead to buffer overrun, which in turn may cause data tampering,
    information disclosure, or denial of service. (CVE-2022-42262)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5415");
  script_set_attribute(attribute:"solution", value:
"Update NVIDIA vGPU Manager software to version 11.11, 13.6, 14.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/14");

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
  { 'min_version' : '450', 'fixed_version' : '450.216.04',   'fixed_display' : '11.11 (450.216.04)' },
  { 'min_version' : '470', 'fixed_version' : '470.161.02',   'fixed_display' : '13.6 (470.161.02)' },
  { 'min_version' : '510', 'fixed_version' : '510.108.03', 'fixed_display' : '14.4 (510.108.03)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
