#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190221);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/15");

  script_cve_id("CVE-2023-47537");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");
  script_xref(name:"IAVA", value:"2024-A-0079-S");

  script_name(english:"Fortinet Fortigate lack of certificate validation (FG-IR-23-301)");

  script_set_attribute(attribute:"synopsis", value:
"Fortinet Firewall is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of Fortigate installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-23-301 advisory.

  - An improper certificate validation vulnerability in Fortinet FortiOS 7.0.0 - 7.0.13, 7.2.0 - 7.2.6, 7.4.0
    - 7.4.1 and 6.4 all versions allows a remote and unauthenticated attacker to perform a Man-in-the-Middle
    attack on the FortiLink communication channel between the FortiOS device and FortiSwitch. (CVE-2023-47537)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-301");
  script_set_attribute(attribute:"solution", value:
"For 6.4.x, see vendor advisory. For 7.0.x, upgrade to Fortigate version 7.0.16 or later. For 7.2.x, upgrade to Fortigate
version 7.2.7 or later. For 7.4.x, upgrade to Fortigate version 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47537");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

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
  { 'min_version' : '7.0.0', 'max_version' : '7.0.15', 'fixed_version' : '7.0.16', 'fixed_display' : 'Upgrade to upcoming 7.0.16 or above' },
  { 'min_version' : '7.2.0', 'max_version' : '7.2.6', 'fixed_version' : '7.2.7' },
  { 'min_version' : '7.4.0', 'max_version' : '7.4.1', 'fixed_version' : '7.4.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
