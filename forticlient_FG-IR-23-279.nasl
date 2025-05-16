#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216117);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2024-40586");

  script_name(english:"Fortinet FortiClient  (FG-IR-23-279)");

  script_set_attribute(attribute:"synopsis", value:
"remote Windows host is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-279 advisory.

  - An Improper Access Control vulnerability [CWE-284] in FortiClient Windows version 7.4.0, version 7.2.6 and
    below, version 7.0.13 and below may allow a local user to escalate his privileges via FortiSSLVPNd service
    pipe. (CVE-2024-40586)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-279");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FortiClient version 7.0.14 / 7.2.7 / 7.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '7.0.3', 'max_version' : '7.0.13', 'fixed_version' : '7.0.14' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.6', 'fixed_version' : '7.2.7' },
  { 'min_version' : '7.4.0', 'fixed_version' : '7.4.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
