#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155788);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2021-36183");
  script_xref(name:"IAVA", value:"2021-A-0562-S");

  script_name(english:"Fortinet FortiClient Privilege escalation vulnerability (FG-IR-20-079)");

  script_set_attribute(attribute:"synopsis", value:
"remote Windows host is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-20-079 advisory.

  - An improper authorization vulnerability [CWE-285] in FortiClient for Windows versions 7.0.1 and below and
    6.4.2 and below may allow a local unprivileged attacker to escalate their privileges to SYSTEM via the
    named pipe responsible for Forticlient updates. (CVE-2021-36183)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-20-079");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiClientWindows version 6.4.3/7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.4.0', 'max_version' : '6.4.2', 'fixed_version' : '6.4.3' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.1', 'fixed_version' : '7.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
