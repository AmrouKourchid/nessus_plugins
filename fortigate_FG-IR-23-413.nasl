#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197622);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/15");

  script_cve_id("CVE-2023-48784");
  script_xref(name:"IAVA", value:"2024-A-0165-S");

  script_name(english:"Fortinet Fortigate - Format String in CLI command (FG-IR-23-413)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-413 advisory.

  - A use of externally-controlled format string vulnerability [CWE-134] in FortiOS version 7.4.1 and below,
    version 7.2.7 and below, 7.0 all versions, 6.4 all versions command line interface may allow a local
    privileged attacker with super-admin profile and CLI access to execute arbitrary code or commands via
    specially crafted requests. (CVE-2023-48784)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-413");
  script_set_attribute(attribute:"solution", value:
"For 6.4.x, see vendor advisory. For 7.0.x, upgrade to Fortigate version 7.0.16 or later. For 7.2.x, upgrade to Fortigate
version 7.2.8 or later. For 7.4.x, upgrade to Fortigate version 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48784");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { 'min_version' : '7.0.0', 'max_version' : '7.0.15', 'fixed_version' : '7.0.16' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.7', 'fixed_version' : '7.2.8' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.1', 'fixed_version' : '7.4.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
