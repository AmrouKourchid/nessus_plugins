#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200531);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2022-26113");

  script_name(english:"Fortinet FortiClient Arbitrary file write as SYSTEM (FG-IR-22-044)");

  script_set_attribute(attribute:"synopsis", value:
"remote Windows host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-044 advisory.

  - An execution with unnecessary privileges vulnerability [CWE-250] in FortiClientWindows 7.0.0 through
    7.0.3, 6.4.0 through 6.4.7, 6.2.0 through 6.2.9, 6.0.0 through 6.0.10 may allow a local attacker to
    perform an arbitrary file write on the system. (CVE-2022-26113)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-044");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiClientWindows version 6.4.8/7.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26113");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');

if (empty_or_null(get_kb_item('Host/local_checks_enabled'))) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (empty_or_null(get_kb_item('SMB/Registry/Enumerated'))) audit(AUDIT_OS_NOT, 'Windows');

var app_name = 'FortiClient';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.10', 'fixed_version' : '6.4.8' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.9', 'fixed_version' : '6.4.8' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.7', 'fixed_version' : '6.4.8' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.3', 'fixed_version' : '7.0.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
