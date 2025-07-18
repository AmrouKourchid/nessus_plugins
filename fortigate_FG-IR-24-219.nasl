#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214080);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-46668");
  script_xref(name:"IAVA", value:"2025-A-0022");

  script_name(english:"Fortinet Fortigate Multipart Form Data DoS (FG-IR-24-219)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-24-219 advisory.

  - An allocation of resources without limits or throttling vulnerability [CWE-770] in FortiOS versions 7.4.0
    through 7.4.4, versions 7.2.0 through 7.2.8, versions 7.0.0 through 7.0.15, and versions 6.4.0 through
    6.4.15 may allow an unauthenticated remote user to consume all system memory via multiple large file
    uploads. (CVE-2024-46668)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-24-219");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 6.4.16 / 7.0.16 / 7.2.9 / 7.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46668");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
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

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '6.4.0', 'max_version' : '6.4.15', 'fixed_version' : '6.4.16', 'fixed_display' : 'Upgrade to upcoming 6.4.16 or above' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.15', 'fixed_version' : '7.0.16' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.8', 'fixed_version' : '7.2.9' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.4', 'fixed_version' : '7.4.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
