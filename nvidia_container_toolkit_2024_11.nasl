#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-0134");
  script_xref(name:"IAVB", value:"2024-B-0167-S");

  script_name(english:"NVIDIA Container Toolkit < 1.17 Data Tampering");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA Container Toolkit installed on the remote host is prior to 1.17. It is, therefore, affected
by a data tampering vulnerability as referenced in the November 2024 Security Bulletin.

  - NVIDIA Container Toolkit and NVIDIA GPU Operator for Linux contain a UNIX vulnerability where a specially crafted 
    container image can lead to the creation of unauthorized files on the host. The name and location of the files 
    cannot be controlled by an attacker. A successful exploit of this vulnerability might lead to data tampering. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5585");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA Container Toolkit version 1.17 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0134");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:container_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_container_toolkit_nix_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Container Toolkit");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Container Toolkit');

var constraints = [
  { 'fixed_version' : '1.17' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
