#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200815);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/19");

  script_cve_id("CVE-2024-32860");
  script_xref(name:"IAVA", value:"2024-A-0360");

  script_name(english:"Dell Client BIOS Improper Input Validation (DSA-2024-125)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"Dell Client Platform BIOS contains an Improper Input Validation vulnerability in an externally developed component.
A high privileged attacker with local access could potentially exploit this vulnerability, leading to Code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000223440/dsa-2024-125-security-update-for-dell-client-platform-bios-for-an-improper-input-validation-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7de711c8");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  if (model == 'Alienware Area 51m R2') fix = '1.26.0';
  else if (model == 'Alienware Aurora R11') fix = '1.0.24';
  else if (model == 'Alienware Aurora R12') fix = '1.1.25';
  else if (model == 'Alienware Aurora R13') fix = '1.19.0';
  else if (model == 'Alienware Aurora R15') fix = '1.12.0';
  else if (model == 'Alienware Aurora R15 AMD') fix = '1.13.0';
  else if (model == 'Alienware Aurora Ryzen Edition R14') fix = '2.18.0';
  else if (model == 'Alienware m15 R3') fix = '1.27.0';
  else if (model == 'Alienware m15 R4') fix = '1.21.0';
  else if (model == 'Alienware m17 R3') fix = '1.27.0';
  else if (model == 'Alienware m17 R4') fix = '1.21.0';
  else if (model == 'Alienware x14') fix = '1.18.0';
  else if (model == 'Alienware x15 R1') fix = '1.22.0';
  else if (model == 'Alienware x15 R2') fix = '1.20.0';
  else if (model == 'Alienware x17 R1') fix = '1.22.0';
  else if (model == 'Alienware x17 R2') fix = '1.20.0';
  else if (model == 'AURORA R16') fix = '2.7.0';
  else if (model == 'Inspiron 15 3510') fix = '1.19.0';
  else if (model == 'Inspiron 15 3521') fix = '1.14.0';
  else if (model == 'Inspiron 3502') fix = '1.16.0';
  else if (model == 'XPS 8950') fix = '1.19.0';
  else if (model == 'XPS 8960') fix = '2.6.0';
  else audit(AUDIT_HOST_NOT, 'an affected model');
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
