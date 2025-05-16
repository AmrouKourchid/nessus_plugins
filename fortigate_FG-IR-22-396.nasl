#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185607);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/28");

  script_cve_id("CVE-2023-28002");
  script_xref(name:"IAVA", value:"2023-A-0643-S");

  script_name(english:"Fortinet Fortigate VM - Bypass of root file system integrity checks at boot time on VM (FG-IR-22-396)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-396 advisory.

  - An improper validation of integrity check value vulnerability [CWE-354] in FortiOS 7.2.0 through 7.2.3,
    7.0.0 through 7.0.12, 6.4 all versions, 6.2 all versions, 6.0 all versions and FortiProxy 7.2 all
    versions, 7.0 all versions, 2.0 all versions VMs may allow a local attacker with admin privileges to boot
    a malicious image on the device and bypass the filesystem integrity check in place. (CVE-2023-28002)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-396");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 7.0.13 / 7.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
var model = get_kb_item_or_exit("Host/Fortigate/model");
vcf::fortios::verify_product_and_model(product_name:app_name);

# Vulnerability only affects VM models
if ('vm64' >!< tolower(model))
  audit(AUDIT_DEVICE_NOT_VULN, model);

var constraints = [
  { 'min_version' : '6.0', 'fixed_version' : '7.0.13', 'fixed_display' : 'Migrate to a fixed release.' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.12', 'fixed_version' : '7.0.13', 'fixed_display' : 'Migrate to a fixed release.' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.3', 'fixed_version'  : '7.2.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
