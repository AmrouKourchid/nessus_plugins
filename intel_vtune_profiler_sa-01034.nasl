#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197896);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/05");

  script_cve_id("CVE-2023-45320");
  script_xref(name:"IAVA", value:"2024-A-0299");

  script_name(english:"Intel VTune Profiler < 2024.0 Escalation of Privilege");

  script_set_attribute(attribute:"synopsis", value:
"A software performance profiler application installed on the remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Intel VTune Profiler installed on the remote Windows host is prior to 2024.0. It is,
therefore, affected by an escalation of privilege vulnerability. Due to an uncontrolled search path element, an
authenticated, local attacker can elevate their privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01034.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4acaab1a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Intel VTune Profiler version 2024.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:vtune_profiler");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intel_vtune_profiler_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Intel VTune Profiler");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Intel VTune Profiler', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '2024.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
