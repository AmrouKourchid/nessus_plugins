#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206981);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_xref(name:"IAVB", value:"2024-B-0132-S");

  script_name(english:"Golang < 1.22.7, 1.23.x < 1.23.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is either prior to 1.22.7 or 1.23.x prior to 1.23.1. It is, 
therefore, is affected by multiple vulnerabilities:

  - Calling any of the Parse functions on Go source code which contains deeply nested literals can cause a panic due 
    to stack exhaustion. (CVE-2024-34155)

  - Calling Decoder.Decode on a message which contains deeply nested structures can cause a panic due to stack 
    exhaustion. (CVE-2024-34156)

  - Calling Parse on a '// +build' build tag line with deeply nested expressions can cause a panic due to stack 
    exhaustion. (CVE-2024-34158)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-dev/c/S9POB9NCTdk");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.22.7, 1.23.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34158");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '1.22.7' },
  { 'min_version' : '1.23.0', 'fixed_version' : '1.23.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
