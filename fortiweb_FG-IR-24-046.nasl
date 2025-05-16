#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234004);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/22");

  script_cve_id("CVE-2024-26013", "CVE-2024-50565");
  script_xref(name:"IAVA", value:"2024-A-0745");

  script_name(english:"Fortinet FortiWeb No certificate name verification for fgfm connection (FG-IR-24-046)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiWeb installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the FG-IR-24-046 advisory.

  - A improper restriction of communication channel to intended endpoints vulnerability [CWE-923] in Fortinet
    FortiOS version 7.4.0 through 7.4.3, 7.2.0 through 7.2.7, 7.0.0 through 7.0.14, 6.4.0 through 6.4.15 and
    6.2.0 through 6.2.16, Fortinet FortiProxy version 7.4.0 through 7.4.2, 7.2.0 through 7.2.9, 7.0.0 through
    7.0.15 and 2.0.0 through 2.0.14, Fortinet FortiManager version 7.4.0 through 7.4.2, 7.2.0 through 7.2.4,
    7.0.0 through 7.0.11, 6.4.0 through 6.4.14 and 6.2.0 through 6.2.13, Fortinet FortiAnalyzer version 7.4.0
    through 7.4.2, 7.2.0 through 7.2.4, 7.0.0 through 7.0.11, 6.4.0 through 6.4.14 and 6.2.0 through 6.2.13,
    Fortinet FortiVoice version 7.0.0 through 7.0.2, 6.4.0 through 6.4.8 and 6.0.0 through 6.0.12 and Fortinet
    FortiWeb version 7.4.0 through 7.4.2, 7.2.0 through 7.2.10, 7.0.0 through 7.0.10 allows an unauthenticated
    attacker in a man-in-the-middle position to impersonate the management device (FortiCloud server or/and in
    certain conditions, FortiManager), via intercepting the FGFM authentication request between the management
    device and the managed device (CVE-2024-50565)

  - A improper restriction of communication channel to intended endpoints vulnerability [CWE-923] in Fortinet
    FortiOS version 7.4.0 through 7.4.4, 7.2.0 through 7.2.8, 7.0.0 through 7.0.15, 6.4.0 through 6.4.15 and
    before 6.2.16, Fortinet FortiProxy version 7.4.0 through 7.4.2, 7.2.0 through 7.2.9 and before 7.0.15,
    Fortinet FortiManager version 7.4.0 through 7.4.2, 7.2.0 through 7.2.4, 7.0.0 through 7.0.11, 6.4.0
    through 6.4.14 and before 6.2.13, Fortinet FortiAnalyzer version 7.4.0 through 7.4.2, 7.2.0 through 7.2.4,
    7.0.0 through 7.0.11, 6.4.0 through 6.4.14 and before 6.2.13, Fortinet FortiVoice version 7.0.0 through
    7.0.2 before 6.4.8 and Fortinet FortiWeb before 7.4.2 may allow an unauthenticated attacker in a man-in-
    the-middle position to impersonate the management device (FortiCloud server or/and in certain conditions,
    FortiManager), via intercepting the FGFM authentication request between the management device and the
    managed device (CVE-2024-26013)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-046");
  script_set_attribute(attribute:"solution", value:
"For 7.4.x, upgrade to FortiWeb version 7.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50565");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-26013");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiweb");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'FortiWeb';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '7.4.0', 'max_version' : '7.4.2', 'fixed_version' : '7.4.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
