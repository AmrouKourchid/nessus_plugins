#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200812);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/19");

  script_cve_id("CVE-2024-28970");
  script_xref(name:"IAVA", value:"2024-A-0360");

  script_name(english:"Dell Client BIOS DoS (DSA-2024-168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"Dell Client BIOS contains an Out-of-bounds Write vulnerability. A local authenticated malicious user with admin
privileges could potentially exploit this vulnerability, leading to platform denial of service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000225476/dsa-2024-168");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28970");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
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
  if (model == 'Dell G7 7500') fix = '1.32.0';
  else if (model == 'Dell G7 7700') fix = '1.32.0';
  else if (model == 'Inspiron 14 Plus 7440') fix = '1.6.0';
  else if (model == 'Inspiron 16 7640 2-in-1') fix = '1.4.0';
  else if (model == 'Inspiron 16 Plus 7640') fix = '1.6.0';
  else if (model == 'Inspiron 24 5420 All-in-One') fix = '1.11.0';
  else if (model == 'Inspiron 27 7720 All-in-One') fix = '1.11.0';
  else if (model == 'Inspiron 5402') fix = '1.30.0';
  else if (model == 'Inspiron 5409') fix = '1.30.0';
  else if (model == 'Inspiron 5502') fix = '1.30.0';
  else if (model == 'Inspiron 5509') fix = '1.30.0';
  else if (model == 'Precision 3660') fix = '2.14.0';
  else if (model == 'Vostro 5402') fix = '1.30.0';
  else if (model == 'Vostro 5502') fix = '1.30.0';
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
