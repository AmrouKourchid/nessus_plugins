#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187948);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2023-44250");
  script_xref(name:"IAVA", value:"2024-A-0019-S");

  script_name(english:"Fortinet FortiProxy Privilage Escalation (FG-IR-23-315)");

  script_set_attribute(attribute:"synopsis", value:
"The version of FortiProxy installed on the remote host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiProxy installed on the remote host is prior to tested version. It is, therefore, affected by an 
improper privilege management vulnerability [CWE-269] in a FortiOS & FortiProxy HA cluster may allow an authenticated 
attacker to perform elevated actions via crafted HTTP or HTTPS requests. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-23-315");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiProxy version 7.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44250");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortiproxy");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/FortiProxy/version");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_fortios.inc');

var app_name = 'FortiProxy';
var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/FortiProxy/version');
vcf::fortios::verify_product_and_model(product_name:app_name);

var constraints = [
  { 'min_version' : '7.4.0', 'fixed_version' : '7.4.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
