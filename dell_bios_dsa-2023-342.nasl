#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187382);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id("CVE-2023-39251");
  script_xref(name:"IAVA", value:"2023-A-0706");

  script_name(english:"Dell Client BIOS Improper Authentication (DSA-2023-342)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by a improper 
input validation vulnerability. A malicious user with physical access to the system may potentially exploit 
this vulnerability in order to corrupt memory on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000217707/dsa-2023-342
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651cbed3");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  if (model == 'Inspiron 7510') fix = '1.20.0';
  else if (model == 'Inspiron 7610') fix = '1.20.0';
  else if (model == 'Latitude 5521') fix = '1.27.0';
  else if (model == 'Latitude 5430 Rugged') fix = '1.23.0';
  else if (model == 'Latitude 7330 Rugged') fix = '1.23.0';
  else if (model == 'Precision 3561') fix = '1.27.0';
  else if (model == 'Precision 5560') fix = '1.25.0';
  else if (model == 'Precision 5760') fix = '1.24.0';
  else if (model == 'Precision 7560') fix = '1.27.0';
  else if (model == 'Precision 7760') fix = '1.27.0';
  else if (model == 'Vostro 7510') fix = '1.20.0';
  else if (model == 'XPS 15 9510') fix = '1.25.0';
  else if (model == 'XPS 17 9710') fix = '1.24.0';
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