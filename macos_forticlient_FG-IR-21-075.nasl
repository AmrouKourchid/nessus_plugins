#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200537);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/29");

  script_cve_id("CVE-2021-41028");

  script_name(english:"Fortinet FortiClient Telemetry protocol is vulnerable to a MitM (FG-IR-21-075) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"remote Mac host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-21-075 advisory.

  - A combination of a use of hard-coded cryptographic key vulnerability [CWE-321] in FortiClientEMS 7.0.1 and
    below, 6.4.6 and below and an improper certificate validation vulnerability [CWE-297] in
    FortiClientWindows, FortiClientLinux and FortiClientMac 7.0.1 and below, 6.4.6 and below may allow an
    unauthenticated and network adjacent attacker to perform a man-in-the-middle attack between the EMS and
    the FCT via the telemetry protocol. (CVE-2021-41028)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-075");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiClientWindows version 6.4.7/7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41028");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)");

  exit(0);
}

include('vcf.inc');

if (empty_or_null(get_kb_item('Host/local_checks_enabled'))) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (empty_or_null(get_kb_item('Host/MacOSX/Version'))) audit(AUDIT_OS_NOT, 'Mac OS');

var app_name = 'FortiClient (macOS)';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '6.4.0', 'max_version' : '6.4.6', 'fixed_version' : '6.4.7' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.1', 'fixed_version' : '7.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
