#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200355);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/27");

  script_cve_id("CVE-2024-23111");

  script_name(english:"Fortinet Fortigate xss (FG-IR-23-471)");

  script_set_attribute(attribute:"synopsis", value:
"Remote host is affected by a xss vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-471 advisory.

  - An improper neutralization of input during web page Generation ('Cross-site Scripting') vulnerability
    [CWE-79] in FortiOS version 7.4.3 and below, 7.2 all versions, 7.0 all versions and FortiProxy version
    7.4.2 and below, 7.2 all versions, 7.0 all versions reboot page may allow a remote privileged attacker
    with super-admin access to execute JavaScript code via crafted HTTP GET requests. (CVE-2024-23111)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-471");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortigate version 7.0.14 / 7.2.8 / 7.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23111");

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

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");

  exit(0);
}

include('vcf_extras_fortios.inc');

var app_name = 'Fortigate';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Fortigate/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.13', 'fixed_version' : '7.0.14' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.7', 'fixed_version' : '7.2.8' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.3', 'fixed_version' : '7.4.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
