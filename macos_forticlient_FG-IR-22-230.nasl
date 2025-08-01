#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206884);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2022-45856");
  script_xref(name:"IAVA", value:"2024-A-0260-S");

  script_name(english:"Fortinet FortiClient (All) - Lack of client-side certificate validation using SAML SSO (FG-IR-22-230) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"remote Mac host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-230 advisory.

  - An improper certificate validation vulnerability [CWE-295] in FortiClientWindows 6.4 all versions, 7.0.0
    through 7.0.7, FortiClientMac 6.4 all versions, 7.0 all versions, 7.2.0 through 7.2.4, FortiClientLinux
    6.4 all versions, 7.0 all versions, 7.2.0 through 7.2.4, FortiClientAndroid 6.4 all versions, 7.0 all
    versions, 7.2.0 and FortiClientiOS 5.6 all versions, 6.0.0 through 6.0.1, 7.0.0 through 7.0.6 SAML SSO
    feature may allow an unauthenticated attacker to man-in-the-middle the communication between the
    FortiClient and both the service provider and the identity provider. (CVE-2022-45856)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FortiClient version 6.4.999999 / 7.0.999999 / 7.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45856");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_version' : '6.4', 'fixed_version' : '6.4.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.4', 'fixed_version' : '7.2.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
