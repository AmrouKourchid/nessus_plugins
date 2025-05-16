#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211690);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id(
    "CVE-2024-28881",
    "CVE-2024-28952",
    "CVE-2024-36245",
    "CVE-2024-37027",
    "CVE-2024-39284"
  );
  script_xref(name:"IAVA", value:"2024-A-0747");
  script_xref(name:"IAVA", value:"2025-A-0098");

  script_name(english:"Intel oneAPI Base Toolkit < 2024.2.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities exist in Intel oneAPI Base Toolkit versions prior to 2024.2.0. See vendor advisory for more 
details. 

  - Uncontrolled search path for some Intel® Fortran Compiler Classic software before version 2021.13 may allow an
    authenticated user to potentially enable escalation of privilege via local access. (CVE-2024-28881)

  - Uncontrolled search path for some Intel® IPP software for Windows before version 2021.12.0 may allow an
    authenticated user to potentially enable escalation of privilege via local access. (CVE-2024-28952)

  - Uncontrolled search path element in some Intel® VTune™ Profiler software before version 2024.2.0 may allow an
    authenticated user to potentially enable escalation of privilege via local access. (CVE-2024-36245)

  - Improper Input validation in some Intel® VTune™ Profiler software before version 2024.2.0 may allow an authenticated
    user to potentially enable denial of service via local access. (CVE-2024-37027)

  - Uncontrolled search path for some Intel® Advisor software before version 2024.2 may allow an authenticated user to
    potentially enable escalation of privilege via local access. (CVE-2024-39284)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01140.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7821d65");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01173.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1a60a8b");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01187.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e84c84ff");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01208.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?073043c7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel oneAPI Base Toolkit 2024.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28881");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-39284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:oneapi_base_toolkit");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_oneapi_base_toolkit_win_installed.nbin");
  script_require_keys("installed_sw/oneAPI Base Toolkit");

  exit(0);
}

include('vcf.inc');

var app = 'oneAPI Base Toolkit';

var constraints = [{'fixed_version' : '2024.2.0'}];

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
