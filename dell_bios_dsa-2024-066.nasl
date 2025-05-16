#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193516);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2024-22448");
  script_xref(name:"IAVA", value:"2024-A-0231");

  script_name(english:"Dell Client BIOS Out-Of-Bounds Write Vulnerability (DSA-2024-066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by an Out-of-Bounds Write 
Vulnerability that could be exploited by malicious users to compromise the affected system. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000221744/dsa-2024-066");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  if (model == 'Alienware m15 R6') fix = '1.29.0';
  else if (model == 'Alienware m16 R1') fix = '1.16.0';
  else if (model == 'Alienware m18 R1') fix = '1.16.0';
  else if (model == 'Alienware x14 R2') fix = '1.13.0';
  else if (model == 'Alienware x16 R1') fix = '1.13.0';
  else if (model == 'Dell G15 5511') fix = '1.28.0';
  else if (model == 'Dell G15 5530') fix = '1.14.0';
  else if (model == 'Dell G16 7630') fix = '1.14.0';
  else if (model == 'Dell G3 3500') fix = '1.29.0';
  else if (model == 'Dell G5 5500') fix = '1.29.0';
  else if (model == 'Dell G7 7500') fix = '1.31.0';
  else if (model == 'Dell G7 7700') fix = '1.31.0';
  else if (model == 'Inspiron 13 5330') fix = '1.14.0';
  else if (model == 'Inspiron 15 3530') fix = '1.10.0';
  else if (model == 'Inspiron 3030S') fix = '1.3.0';
  else if (model == 'Inspiron 5301') fix = '1.32.0';
  else if (model == 'Inspiron 5400/5401') fix = '1.27.0';
  else if (model == 'Inspiron 5401 AIO') fix = '1.27.0';
  else if (model == 'Inspiron 5402') fix = '1.29.0';
  else if (model == 'Inspiron 5409') fix = '1.29.0';
  else if (model == 'Inspiron 5502') fix = '1.29.0';
  else if (model == 'Inspiron 5509') fix = '1.29.0';
  else if (model == 'Inspiron 7300') fix = '1.32.0';
  else if (model == 'Inspiron 7400') fix = '1.32.0';
  else if (model == 'Inspiron 7700 AIO') fix = '1.27.0';
  else if (model == 'Latitude 5310') fix = '1.23.0';
  else if (model == 'Latitude 5310 2-in-1') fix = '1.23.0';
  else if (model == 'Latitude 5330') fix = '1.21.0';
  else if (model == 'Latitude 5340') fix = '1.12.0';
  else if (model == 'Latitude 5531') fix = '1.22.0';
  else if (model == 'Latitude 5540') fix = '1.12.0';
  else if (model == 'Latitude 7320') fix = '1.34.2';
  else if (model == 'Latitude 7340') fix = '1.13.0';
  else if (model == 'Latitude 7420') fix = '1.34.2';
  else if (model == 'Latitude 7520') fix = '1.34.2';
  else if (model == 'Latitude 9330') fix = '1.19.0';
  else if (model == 'Latitude 9420') fix = '1.29.0';
  else if (model == 'Latitude 9430') fix = '1.22.0';
  else if (model == 'Latitude 9440 2-in-1') fix = '1.10.0';
  else if (model == 'OptiPlex Micro 7010 / OptiPlex Micro Plus 7010') fix = '1.13.1';
  else if (model == 'OptiPlex Small Form Factor 7010 / OptiPlex Small Form Factor Plus 7010') fix = '1.13.1';
  else if (model == 'OptiPlex Tower 7010 / OptiPlex Tower Plus 7010') fix = '1.13.1';
  else if (model == 'Precision 3440') fix = '1.25.0';
  else if (model == 'Precision 3571') fix = '1.22.0';
  else if (model == 'Precision 3580') fix = '1.12.0';
  else if (model == 'Precision 3581') fix = '1.12.0';
  else if (model == 'Precision 3660') fix = '2.13.0';
  else if (model == 'Precision 5570') fix = '1.22.0';
  else if (model == 'Precision 5750') fix = '1.29.0';
  else if (model == 'Precision 5770') fix = '1.24.0';
  else if (model == 'Vostro 14 3430') fix = '1.10.0';
  else if (model == 'Vostro 15 3530') fix = '1.10.0';
  else if (model == 'Vostro 3030S') fix = '1.3.0';
  else if (model == 'Vostro 5301') fix = '1.32.0';
  else if (model == 'Vostro 5402') fix = '1.29.0';
  else if (model == 'Vostro 5502') fix = '1.29.0';
  else if (model == 'Vostro 5880') fix = '1.25.0';
  else if (model == 'XPS 17 9700') fix = '1.29.0';
  else if (model == 'XPS 17 9720') fix = '1.24.0';
  else if (model == 'XPS 17 9730') fix = '1.11.0';
  else if (model == 'XPS 9315 2-in-1') fix = '1.15.0';
  else
  {
  audit(AUDIT_HOST_NOT, 'an affected model');
  }
}
else
{
  exit(0, 'The model of the device running the Dell BIOS could not be identified.');
}

var constraints = [{ 'fixed_version' : fix, 'fixed_display': fix + ' for ' + model }];
# Have a more useful audit message
app_info.app = 'Dell System BIOS for ' + model;

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
