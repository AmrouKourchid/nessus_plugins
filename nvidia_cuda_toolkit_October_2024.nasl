#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208118);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-0123", "CVE-2024-0124", "CVE-2024-0125");
  script_xref(name:"IAVB", value:"2024-B-0146-S");

  script_name(english:"NVIDIA CUDA Toolkit < 12.6.77 (12.6U2) Multiple Vulnerabilities (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is prior to 12.6.77 (12.6U2). It is, therefore, affected
by multiple vulnerabilities as referenced in the October 2024 advisory.

  - NVIDIA CUDA toolkit for Windows and Linux contains a vulnerability in the nvdisasm command line tool where
    an attacker may cause an improper validation in input issue by tricking the user into running nvdisasm on a
    malicious ELF file. A successful exploit of this vulnerability may lead to denial of service. (CVE-2024-0123)

  - NVIDIA CUDA Toolkit for Windows and Linux contains a vulnerability in the nvdisam command line tool, where a
    user can cause nvdisasm to read freed memory by running it on a malformed ELF file. A successful exploit of
    this vulnerability might lead to a limited denial of service. (CVE-2024-0124)

  - NVIDIA CUDA Toolkit for Windows and Linux contains a vulnerability in the nvdisam command line tool, where a
    user can cause a NULL pointer dereference by running nvdisasm on a malformed ELF file. A successful exploit
    of this vulnerability might lead to a limited denial of service. (CVE-2024-0125)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5577/~/security-bulletin%3A-nvidia-cuda-toolkit---october-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86c77f8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit version 12.6.77 (12.6U2) or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0123");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-0125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:cuda_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_cuda_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/NVIDIA CUDA Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA CUDA Toolkit');

var constraints = [
  { 'fixed_version' : '12.6.77', 'fixed_display' : '12.6.77 (12.6U2)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
