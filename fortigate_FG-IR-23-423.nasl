#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200327);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/15");

  script_cve_id("CVE-2024-21754");

  script_name(english:"Fortinet Fortigate Weak key derivation for backup file (FG-IR-23-423)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-423 advisory.

  - A use of password hash with insufficient computational effort vulnerability [CWE-916] affecting FortiOS
    version 7.4.3 and below, 7.2 all versions, 7.0 all versions, 6.4 all versions and FortiProxy version 7.4.2
    and below, 7.2 all versions, 7.0 all versions, 2.0 all versions may allow a privileged attacker with
    super-admin profile and CLI access to decrypting the backup file. (CVE-2024-21754)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-423");
  script_set_attribute(attribute:"solution", value:
"For 6.4.x / 7.0.x, see vendor advisory. For 7.2.x, upgrade to Fortigate version 7.2.9 or later. For 7.4.x, upgrade to
Fortigate version 7.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.4', 'fixed_version' : '6.4.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.0', 'fixed_version' : '7.0.999999', 'fixed_display' : 'See vendor advisory' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.8', 'fixed_version' : '7.2.9' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.3', 'fixed_version' : '7.4.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
