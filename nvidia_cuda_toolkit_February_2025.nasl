#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216913);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id(
    "CVE-2024-53870",
    "CVE-2024-53871",
    "CVE-2024-53872",
    "CVE-2024-53873",
    "CVE-2024-53874",
    "CVE-2024-53875",
    "CVE-2024-53876",
    "CVE-2024-53877",
    "CVE-2024-53878",
    "CVE-2024-53879"
  );
  script_xref(name:"IAVB", value:"2025-B-0033");

  script_name(english:"NVIDIA CUDA Toolkit 12.8.0 Multiple Vulnerabilities (February_2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA CUDA Toolkit installed on the remote host is prior to 12.8.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the February_2025 advisory.

  - NVIDIA CUDA toolkit for all platforms contains a vulnerability in the cuobjdump binary, where a user could
    cause an out-of-bounds read by passing a malformed ELF file to cuobjdump. A successful exploit of this
    vulnerability might lead to a partial denial of service. (CVE-2024-53870, CVE-2024-53872, CVE-2024-53874,
    CVE-2024-53875)

  - CVE202453870  NVIDIA CUDA toolkit for all platforms contains a vulnerability in the cuobjdump binary,
    where a user could cause an out-of-bounds read by passing a malformed ELF file to cuobjdump. A successful
    exploit of this vulnerability might lead to a partial denial of service. (CVE-2024-53870)

  - NVIDIA CUDA toolkit for all platforms contains a vulnerability in the nvdisasm binary, where a user could
    cause an out-of-bounds read by passing a malformed ELF file to nvdisasm. A successful exploit of this
    vulnerability might lead to a partial denial of service. (CVE-2024-53871, CVE-2024-53876)

  - NVIDIA CUDA toolkit for Windows contains a vulnerability in the cuobjdump binary, where a user could cause
    an out-of-bounds read by passing a malformed ELF file to cuobjdump. A successful exploit of this
    vulnerability might lead to a partial denial of service. (CVE-2024-53873)

  - NVIDIA CUDA toolkit for all platforms contains a vulnerability in the nvdisasm binary, where a user could
    cause a NULL pointer exception by passing a malformed ELF file to nvdisasm. A successful exploit of this
    vulnerability might lead to a partial denial of service. (CVE-2024-53877)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5594");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA CUDA Toolkit version 12.8.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:cuda_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_cuda_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/NVIDIA CUDA Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA CUDA Toolkit');

var constraints = [
  { 'fixed_version' : '12.8.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_NOTE
);
