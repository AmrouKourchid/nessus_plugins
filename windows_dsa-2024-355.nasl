#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213250);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-47238");
  script_xref(name:"IAVA", value:"2024-A-0826");

  script_name(english:"Dell Client Platform BIOS Improper Input Validation (dsa-2024-355)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Client Platform BIOS installed on the remote host is missing a security update.
It is, therefore, affected by a vulnerability as referenced in the dsa-2024-355 advisory.

  - Dell Client Platform BIOS contains an Improper Input Validation vulnerability in an externally developed
    component. A high privileged attacker with local access could potentially exploit this vulnerability,
    leading to arbitrary code execution. (CVE-2024-47238)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000227595/dsa-2024-355");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47238");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:edge_gateway_3000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:edge_gateway_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:embedded_box_pc_3000");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Model", "BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

var fix = '';
# Check model
if (model)
{
  if (model =~ 'Edge Gateway 5[0-9]{3}')
    fix = '1.29.0';
  else if (model =~ 'Edge Gateway 3[0-9]{3}')
    fix = '1.19.0';
  else if (model =~ 'Embedded Box PC 3000')
    fix = '1.25.0';
  else
    audit(AUDIT_HOST_NOT, 'an affected model');
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
