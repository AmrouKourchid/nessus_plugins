#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191743);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2022-42265",
    "CVE-2024-0074",
    "CVE-2024-0075",
    "CVE-2024-0077",
    "CVE-2024-0078",
    "CVE-2024-0079"
  );
  script_xref(name:"IAVA", value:"2024-A-0130-S");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for WIndows and Linux contains a vulnerability in the kernel mode data handler, where an
    unprivileged regular user can cause integer overflow, which may lead to denial of service, information disclosure,
    and data tampering. (CVE-2022-42665)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability where an attacker may access a memory location after 
    the end of the buffer. A successful exploit of this vulnerability may lead to denial of service and data tampering. 
    (CVE-2024-0074)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where a user may cause a NULL-pointer 
    dereference by accessing passed parameters the validity of which has not been checked. A successful exploit of 
    this vulnerability may lead to denial of service and limited information disclosure. (CVE-2024-0075)

  - NVIDIA Virtual GPU Manager contains a vulnerability in the vGPU plugin, where it allows a guest OS to allocate 
    resources for which the guest OS is not authorized. A successful exploit of this vulnerability may lead to code 
    execution, denial of service, escalation of privileges, information disclosure, and data tampering. (CVE-2024-0077)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a user in 
    a guest can cause a NULL-pointer dereference in the host, which may lead to denial of service. (CVE-2024-0078)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a user 
    in a guest VM can cause a NULL-pointer dereference in the host. A successful exploit of this vulnerability may 
    lead to denial of service. (CVE-2024-0079)
	
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5520
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20b94e14");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA vGPU Manager software in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0077");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42265");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

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
  { 'min_version' : '470', 'fixed_version' : '470.239.01',   'fixed_display' : '13.10 (470.239.01)' },
  { 'min_version' : '535', 'fixed_version' : '535.161.05',   'fixed_display' : '16.4 (535.161.05)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
