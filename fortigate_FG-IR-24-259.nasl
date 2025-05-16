#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214079);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2024-48884", "CVE-2024-48885");
  script_xref(name:"IAVA", value:"2025-A-0022");

  script_name(english:"Fortinet Fortigate Path traversal in csfd daemon (FG-IR-24-259)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the FG-IR-24-259 advisory.

  - A improper limitation of a pathname to a restricted directory ('path traversal') in Fortinet FortiRecorder
    versions 7.2.0 through 7.2.1, 7.0.0 through 7.0.4, FortiWeb versions 7.6.0, 7.4.0 through 7.4.4, 7.2.0
    through 7.2.10, 7.0.0 through 7.0.10, 6.4.0 through 6.4.3, FortiVoice versions 7.0.0 through 7.0.4, 6.4.0
    through 6.4.9, 6.0.0 through 6.0.12 allows attacker to escalate privilege via specially crafted packets.
    (CVE-2024-48885)

  - A improper limitation of a pathname to a restricted directory ('path traversal') in Fortinet FortiManager
    versions 7.6.0 through 7.6.1, 7.4.1 through 7.4.3, FortiOS versions 7.6.0, 7.4.0 through 7.4.4, 7.2.5
    through 7.2.9, 7.0.0 through 7.0.15, 6.4.0 through 6.4.15, FortiProxy 7.4.0 through 7.4.5, 7.2.0 through
    7.2.11, 7.0.0 through 7.0.18, 2.0.0 through 2.0.14, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0
    through 1.0.7, FortiManager Cloud versions 7.4.1 through 7.4.3 allows attacker to trigger an escalation of
    privilege via specially crafted packets. (CVE-2024-48884)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-259");
  script_set_attribute(attribute:"solution", value:
"For 6.4.x, upgrade to Fortigate version 6.4.16 or later. For 7.0.x, upgrade to Fortigate version 7.0.16 or later. For
7.2.x, upgrade to Fortigate version 7.2.10 or later. For 7.4.x, upgrade to Fortigate version 7.4.5 or later. For 7.6.x,
upgrade to Fortigate version 7.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-48885");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_fortios.inc');

# Since there's a workaround specified in the advisory, we're making this require paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.4.0', 'max_version' : '6.4.15', 'fixed_version' : '6.4.16' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.15', 'fixed_version' : '7.0.16' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.9', 'fixed_version' : '7.2.10' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.4', 'fixed_version' : '7.4.5' },
  { 'min_version' : '7.6.0', 'fixed_version' : '7.6.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
