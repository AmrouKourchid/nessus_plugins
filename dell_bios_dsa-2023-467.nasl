#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191635);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2023-48674");
  script_xref(name:"IAVA", value:"2024-A-0125");

  script_name(english:"Dell Client BIOS DoS (DSA-2023-467)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by an improper NULL
termination vulnerability that can result in a denial of service (DoS) condition. A high-privilege user with network
access to the affected device can send malicious data to the device in order to cause some services to cease to
function.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-us/000220410/dsa-2023-467");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/06");

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
  if (model == 'Precision Tower 3430') fix = '1.28.0';
  else if (model == 'Precision Tower 3431') fix = '1.24.0';
  else if (model == 'Precision 3630 Tower') fix = '2.26.0';
  else if (model == 'Precision 5820 Tower') fix = '2.34.0';
  else if (model == 'Precision 7820 Tower') fix = '2.38.0';
  else if (model == 'Precision 7920 Tower') fix = '2.38.0';
  else if (model == 'Latitude 5280') fix = '1.34.0';
  else if (model == 'Latitude 5288') fix = '1.34.0';
  else if (model == 'Latitude 5290') fix = '1.33.0';
  else if (model == 'Latitude 5290 2-in-1') fix = '1.32.0';
  else if (model == 'Latitude 5300') fix = '1.29.0';
  else if (model == 'Latitude 5300 2-in-1') fix = '1.29.0';
  else if (model == 'Latitude 5310') fix = '1.22.0';
  else if (model == 'Latitude 5310 2-in-1') fix = '1.22.0';
  else if (model == 'Latitude 5320') fix = '1.34.0';
  else if (model == 'Latitude 5330') fix = '1.19.0';
  else if (model == 'Latitude 5340') fix = '1.10.1';
  else if (model == 'Latitude 5400') fix = '1.28.0';
  else if (model == 'Latitude 5401') fix = '1.29.0';
  else if (model == 'Latitude 5410') fix = '1.25.0';
  else if (model == 'Latitude 5411') fix = '1.26.0';
  else if (model == 'Latitude 5420') fix = '1.34.1';
  else if (model == 'Latitude 5420 Rugged') fix = '1.30.0';
  else if (model == 'Latitude 5421') fix = '1.27.1';
  else if (model == 'Latitude 5424 Rugged') fix = '1.30.0';
  else if (model == 'Latitude 5430') fix = '1.19.0';
  else if (model == 'Latitude 5430 Rugged') fix = '1.24.0';
  else if (model == 'Latitude 5431') fix = '1.19.0';
  else if (model == 'Latitude 5440') fix = '1.11.0';
  else if (model == 'Latitude 5480') fix = '1.34.0';
  else if (model == 'Latitude 5488') fix = '1.34.0';
  else if (model == 'Latitude 5490') fix = '1.33.0';
  else if (model == 'Latitude 5491') fix = '1.31.0';
  else if (model == 'Latitude 5500') fix = '1.28.0';
  else if (model == 'Latitude 5501') fix = '1.29.0';
  else if (model == 'Latitude 5510') fix = '1.25.0';
  else if (model == 'Latitude 5511') fix = '1.26.0';
  else if (model == 'Latitude 5520') fix = '1.34.0';
  else if (model == 'Latitude 5521') fix = '1.28.0';
  else if (model == 'Latitude 5530') fix = '1.19.0';
  else if (model == 'Latitude 5531') fix = '1.20.0';
  else if (model == 'Latitude 5540') fix = '1.10.1';
  else if (model == 'Latitude 5580') fix = '1.34.0';
  else if (model == 'Latitude 5590') fix = '1.33.0';
  else if (model == 'Latitude 5591') fix = '1.31.0';
  else if (model == 'Latitude 7200 2-in-1') fix = '1.27.0';
  else if (model == 'Latitude 7210 2-in-1') fix = '1.27.0';
  else if (model == 'Latitude 7212 Rugged Extreme Tablet') fix = '1.48.0';
  else if (model == 'Latitude 7220 Rugged Extreme Tablet') fix = '1.34.1';
  else if (model == 'Latitude 7230 Rugged Extreme Tablet') fix = '1.12.0';
  else if (model == 'Latitude 7280') fix = '1.35.0';
  else if (model == 'Latitude 7285') fix = '1.24.0';
  else if (model == 'Latitude 7290') fix = '1.36.0';
  else if (model == 'Latitude 7300') fix = '1.29.0';
  else if (model == 'Latitude 7310') fix = '1.27.0';
  else if (model == 'Latitude 7320 Detachable') fix = '1.28.0';
  else if (model == 'Latitude 7330') fix = '1.20.0';
  else if (model == 'Latitude 7330 Rugged Extreme') fix = '1.24.0';
  else if (model == 'Latitude 7340') fix = '1.11.0';
  else if (model == 'Latitude 7380') fix = '1.35.0';
  else if (model == 'Latitude 7390') fix = '1.36.0';
  else if (model == 'Latitude 7400') fix = '1.29.0';
  else if (model == 'Latitude 7400 2-in-1') fix = '1.26.0';
  else if (model == 'Latitude 7410') fix = '1.27.0';
  else if (model == 'Latitude 7424 Rugged Extreme') fix = '1.30.0';
  else if (model == 'Latitude 7430') fix = '1.20.0';
  else if (model == 'Latitude 7440') fix = '1.11.0';
  else if (model == 'Latitude 7480') fix = '1.35.0';
  else if (model == 'Latitude 7490') fix = '1.36.0';
  else if (model == 'Latitude 7530') fix = '1.20.0';
  else if (model == 'Latitude 7640') fix = '1.11.0';
  else if (model == 'Latitude 9330') fix = '1.17.0';
  else if (model == 'Latitude 9410') fix = '1.26.0';
  else if (model == 'Latitude 9420') fix = '1.27.0';
  else if (model == 'Latitude 9430') fix = '1.20.0';
  else if (model == 'Latitude 9440 2-in-1') fix = '1.8.0';
  else if (model == 'Latitude 9510') fix = '1.25.0';
  else if (model == 'Latitude 9520') fix = '1.28.0';
  else if (model == 'Latitude Rugged 7220EX Rugged Extreme Tablet') fix = '1.34.1';
  else if (model == 'OptiPlex 7000') fix = '1.19.0';
  else if (model == 'OptiPlex 7060') fix = '1.28.0';
  else if (model == 'OptiPlex 7070') fix = '1.25.0';
  else if (model == 'OptiPlex 7070 Ultra') fix = '1.23.0';
  else if (model == 'OptiPlex 7071') fix = '1.24.0';
  else if (model == 'OptiPlex 7080') fix = '1.24.1';
  else if (model == 'OptiPlex 7090') fix = '1.22.2';
  else if (model == 'OptiPlex 7090 UFF') fix = '1.25.0';
  else if (model == 'OptiPlex 7400 AIO') fix = '1.1.37';
  else if (model == 'OptiPlex 7450 AIO') fix = '1.30.0';
  else if (model == 'OptiPlex 7460 AIO') fix = '1.31.0';
  else if (model == 'OptiPlex 7470 AIO') fix = '1.27.0';
  else if (model == 'OptiPlex 7480 AIO') fix = '1.28.0';
  else if (model == 'OptiPlex 7490 AIO') fix = '1.27.1';
  else if (model == 'OptiPlex 7760 AIO') fix = '1.31.0';
  else if (model == 'OptiPlex 7770 AIO') fix = '1.27.0';
  else if (model == 'OptiPlex 7780 AIO') fix = '1.28.0';
  else if (model == 'OptiPlex AIO 7410 35W') fix = '1.11.0';
  else if (model == 'OptiPlex AIO 7410 65W') fix = '1.11.0';
  else if (model == 'OptiPlex AIO Plus 7410') fix = '1.11.0';
  else if (model == 'OptiPlex Micro 7010') fix = '1.11.0';
  else if (model == 'OptiPlex Micro Plus 7010') fix = '1.11.0';
  else if (model == 'OptiPlex SFF 7010') fix = '1.11.0';
  else if (model == 'OptiPlex SFF Plus 7010') fix = '1.11.0';
  else if (model == 'OptiPlex Tower 7010') fix = '1.11.0';
  else if (model == 'OptiPlex Tower Plus 7010') fix = '1.11.0';
  else if (model == 'OptiPlex XE3') fix = '1.28.0';
  else if (model == 'OptiPlex XE4 series') fix = '1.19.0';
  else if (model == 'Precision 3240 Compact') fix = '1.24.0';
  else if (model == 'Precision 3260') fix = '3.1.1';
  else if (model == 'Precision Tower 3420') fix = '2.28.0';
  else if (model == 'Precision 3440') fix = '1.24.1';
  else if (model == 'Precision 3450') fix = '1.22.1';
  else if (model == 'Precision 3460') fix = '3.1.1';
  else if (model == 'Precision 3470') fix = '1.19.0';
  else if (model == 'Precision 3480') fix = '1.11.0';
  else if (model == 'Precision 3520') fix = '1.34.0';
  else if (model == 'Precision 3530') fix = '1.31.0';
  else if (model == 'Precision 3540') fix = '1.28.0';
  else if (model == 'Precision 3541') fix = '1.29.0';
  else if (model == 'Precision 3550') fix = '1.25.0';
  else if (model == 'Precision 3551') fix = '1.26.0';
  else if (model == 'Precision 3560') fix = '1.34.0';
  else if (model == 'Precision 3561') fix = '1.28.0';
  else if (model == 'Precision 3570') fix = '1.19.0';
  else if (model == 'Precision 3571') fix = '1.20.0';
  else if (model == 'Precision 3580') fix = '1.10.1';
  else if (model == 'Precision 3581') fix = '1.10.1';
  else if (model == 'Precision Tower 3620') fix = '2.28.0';
  else if (model == 'Precision 3640 Tower') fix = '1.28.0';
  else if (model == 'Precision 3650 Tower') fix = '1.28.1';
  else if (model == 'Precision 3660') fix = '2.11.1';
  else if (model == 'Precision 3930 Rack') fix = '2.29.0';
  else if (model == 'Precision 5470') fix = '1.19.0';
  else if (model == 'Precision 5480') fix = '1.8.0';
  else if (model == 'Precision 5520') fix = '1.36.0';
  else if (model == 'Precision 5530') fix = '1.35.0';
  else if (model == 'Precision 5530 2-in-1') fix = '1.29.8';
  else if (model == 'Precision 5540') fix = '1.26.0';
  else if (model == 'Precision 5550') fix = '1.26.0';
  else if (model == 'Precision 5560') fix = '1.26.0';
  else if (model == 'Precision 5570') fix = '1.20.0';
  else if (model == 'Precision 5720 AIO') fix = '2.23.0';
  else if (model == 'Precision 5750') fix = '1.28.0';
  else if (model == 'Precision 5760') fix = '1.25.1';
  else if (model == 'Precision 5770') fix = '1.22.0';
  else if (model == 'Precision 7520') fix = '1.34.0';
  else if (model == 'Precision 7530') fix = '1.32.0';
  else if (model == 'Precision 7540') fix = '1.30.0';
  else if (model == 'Precision 7550') fix = '1.28.0';
  else if (model == 'Precision 7560') fix = '1.28.0';
  else if (model == 'Precision 7680') fix = '1.9.0';
  else if (model == 'Precision 7720') fix = '1.34.0';
  else if (model == 'Precision 7730') fix = '1.32.0';
  else if (model == 'Precision 7740') fix = '1.30.0';
  else if (model == 'Precision 7750') fix = '1.28.0';
  else if (model == 'Precision 7760') fix = '1.28.0';
  else if (model == 'Precision 7780') fix = '1.9.0';
  else if (model == 'XPS 13 9310') fix = '3.20.0';
  else if (model == 'XPS 13 9310 2-in-1') fix = '2.22.0';
  else if (model == 'XPS 9315') fix = '1.17.0';
  else if (model == 'XPS 9320') fix = '2.9.0';
  else if (model == 'XPS 15 9520') fix = '1.20.0';
  else if (model == 'XPS 17 9720') fix = '1.22.0';
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
