#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216935);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2025-52541");
  script_xref(name:"IAVA", value:"2025-A-0129");

  script_name(english:"Dell Client BIOS Weak Authentication (DSA-2025-021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"Dell Client Platform BIOS contains a Weak Authentication vulnerability. A high privileged attacker with local access
could potentially exploit this vulnerability, leading to Elevation of Privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-cy/000258429/dsa-2025-021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70e9e973");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-52541");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_wmi.nbin");
  script_require_keys("BIOS/Model", "BIOS/Version", "BIOS/Vendor");

  exit(0);
}

include('vcf_extras.inc');

var app_name = 'Dell Inc.';
var app_info = vcf::dell_bios_win::get_app_info(app:app_name);
var model = app_info['model'];

var fix = '';
if (model)
{
    if (model == 'Alienware m15 R6') fix = '1.34.0';
  else if (model == 'Alienware m15 R7') fix = '1.28.0';
  else if (model == 'Alienware m16 R1') fix = '1.21.0';
  else if (model == 'Alienware m16 R2') fix = '1.8.0';
  else if (model == 'Alienware m18 R1') fix = '1.21.0';
  else if (model == 'Alienware M18 R2') fix = '1.9.0';
  else if (model == 'Alienware x14 R2') fix = '1.17.0';
  else if (model == 'Alienware x16 R1') fix = '1.17.0';
  else if (model == 'Alienware X16 R2') fix = '1.7.0';
  else if (model == 'ChengMing 3900') fix = '1.26.0';
  else if (model == 'ChengMing 3910/3911') fix = '1.20.0';
  else if (model == 'ChengMing 3990') fix = '1.31.1';
  else if (model == 'ChengMing 3991') fix = '1.31.1';
  else if (model == 'Dell Edge Gateway 5000') fix = '1.30.0';
  else if (model == 'Dell G15 5510') fix = '1.29.0';
  else if (model == 'Dell G15 5511') fix = '1.32.0';
  else if (model == 'Dell G15 5520') fix = '1.28.0';
  else if (model == 'Dell G15 5530') fix = '1.21.1';
  else if (model == 'Dell G16 7620') fix = '1.28.0';
  else if (model == 'Dell G16 7630') fix = '1.21.1';
  else if (model == 'Dell G5 5000') fix = '1.25.1';
  else if (model == 'Dell Precision 3430 Tower') fix = '1.33.0';
  else if (model == 'Dell Precision 3431 Tower') fix = '1.31.0';
  else if (model == 'Dell Precision 3630 Tower') fix = '2.31.0';
  else if (model == 'Dell Precision 5820 Tower') fix = '2.39.0';
  else if (model == 'Dell Precision 7820 Tower') fix = '2.43.0';
  else if (model == 'Dell Precision 7920 Tower') fix = '2.43.0';
  else if (model == 'Edge Gateway 3000 series') fix = '1.20.0';
  else if (model == 'Embedded Box PC 3000') fix = '1.26.0';
  else if (model == 'Embedded Box PC 5000') fix = '1.27.0';
  else if (model == 'Inspiron 13 5310') fix = '2.31.0';
  else if (model == 'Inspiron 13 5320') fix = '1.22.0';
  else if (model == 'Inspiron 13 5330') fix = '1.18.0';
  else if (model == 'Inspiron 14  5410/5418') fix = '2.30.0';
  else if (model == 'Inspiron 14 5420') fix = '1.24.0';
  else if (model == 'Inspiron 14 5430') fix = '1.17.0';
  else if (model == 'Inspiron 14 5440') fix = '1.8.0';
  else if (model == 'Inspiron 14 7420 2-in-1') fix = '1.24.0';
  else if (model == 'Inspiron 14 7430 2-in-1') fix = '1.17.0';
  else if (model == 'Inspiron 14 7440 2-in-1') fix = '1.8.0';
  else if (model == 'Inspiron 14 Plus 7420') fix = '1.25.0';
  else if (model == 'Inspiron 14 Plus 7430') fix = '1.18.0';
  else if (model == 'Inspiron 14 Plus 7440') fix = '1.10.0';
  else if (model == 'Inspiron 15 3511') fix = '1.34.0';
  else if (model == 'Inspiron 15 3511') fix = '1.33.0';
  else if (model == 'Inspiron 15 3520') fix = '1.28.0';
  else if (model == 'Inspiron 15 3530') fix = '1.14.0';
  else if (model == 'Inspiron 15 5510/5518') fix = '2.30.0';
  else if (model == 'Inspiron 15 7510') fix = '1.28.0';
  else if (model == 'Inspiron 16 5620') fix = '1.24.0';
  else if (model == 'Inspiron 16 5630') fix = '1.17.0';
  else if (model == 'Inspiron 16 5640') fix = '1.6.1';
  else if (model == 'Inspiron 16 7610') fix = '1.28.0';
  else if (model == 'Inspiron 16 7620 2-in-1') fix = '1.24.0';
  else if (model == 'Inspiron 16 7630 2-in-1') fix = '1.17.0';
  else if (model == 'Inspiron 16 7640 2-in-1') fix = '1.8.0';
  else if (model == 'Inspiron 16 Plus 7620') fix = '1.25.0';
  else if (model == 'Inspiron 16 Plus 7630') fix = '1.18.0';
  else if (model == 'Inspiron 16 Plus 7640') fix = '1.10.0';
  else if (model == 'Inspiron 24 5420 All-in-One') fix = '1.15.1';
  else if (model == 'Inspiron 24 5430 All-in-One') fix = '1.7.0';
  else if (model == 'Inspiron 27 7720 All-in-One') fix = '1.15.1';
  else if (model == 'Inspiron 27 7730 All-in-One') fix = '1.7.0';
  else if (model == 'Inspiron 3020 Desktop') fix = '1.20.0';
  else if (model == 'Inspiron 3020 Small Desktop') fix = '1.20.0';
  else if (model == 'Inspiron 3030') fix = '1.10.0';
  else if (model == 'Inspiron 3030S') fix = '1.10.0';
  else if (model == 'Inspiron 3501') fix = '1.34.0';
  else if (model == 'Inspiron 3880') fix = '1.31.1';
  else if (model == 'Inspiron 3881') fix = '1.31.1';
  else if (model == 'Inspiron 3891') fix = '1.30.0';
  else if (model == 'Inspiron 3910') fix = '1.26.0';
  else if (model == 'Inspiron 5301') fix = '1.36.1';
  else if (model == 'Inspiron 5400/5401') fix = '1.33.1';
  else if (model == 'Inspiron 5401 AIO') fix = '1.33.1';
  else if (model == 'Inspiron 5402') fix = '1.33.1';
  else if (model == 'Inspiron 5406 2-in-1') fix = '1.33.1';
  else if (model == 'Inspiron 5409') fix = '1.33.1';
  else if (model == 'Inspiron 5410') fix = '2.30.0';
  else if (model == 'Inspiron 5410 All-in-One') fix = '1.25.0';
  else if (model == 'Inspiron 5502') fix = '1.33.1';
  else if (model == 'Inspiron 5509') fix = '1.33.1';
  else if (model == 'Inspiron 7300') fix = '1.36.1';
  else if (model == 'Inspiron 7306 2-in-1') fix = '1.33.1';
  else if (model == 'Inspiron 7400') fix = '1.36.1';
  else if (model == 'Inspiron 7500') fix = '1.31.1';
  else if (model == 'Inspiron 7501') fix = '1.31.1';
  else if (model == 'Inspiron 7506 2-in-1') fix = '1.33.1';
  else if (model == 'Inspiron 7700 All-In-One') fix = '1.33.1';
  else if (model == 'Inspiron 7706 2-in-1') fix = '1.33.1';
  else if (model == 'Inspiron 7710 All-in-One') fix = '1.25.0';
  else if (model == 'Latitude 12 Rugged Extreme 7214') fix = '1.48.0';
  else if (model == 'Latitude 3120') fix = '1.31.1';
  else if (model == 'Latitude 3140') fix = '1.18.0';
  else if (model == 'Latitude 3140 2in1') fix = '1.18.0';
  else if (model == 'Latitude 3180') fix = '1.30.0';
  else if (model == 'Latitude 3189') fix = '1.30.0';
  else if (model == 'Latitude 3190') fix = '1.37.0';
  else if (model == 'Latitude 3190 2-in-1') fix = '1.37.0';
  else if (model == 'Latitude 3300') fix = '1.31.0';
  else if (model == 'Latitude 3310') fix = '1.27.1';
  else if (model == 'Latitude 3310 2-In-1') fix = '1.26.1';
  else if (model == 'Latitude 3320') fix = '1.33.0';
  else if (model == 'Latitude 3330') fix = '1.25.0';
  else if (model == 'Latitude 3340') fix = '1.16.0';
  else if (model == 'Latitude 3390 2-in-1') fix = '1.34.0';
  else if (model == 'Latitude 3400') fix = '1.35.1';
  else if (model == 'Latitude 3410') fix = '1.32.1';
  else if (model == 'Latitude 3420') fix = '1.38.0';
  else if (model == 'Latitude 3430') fix = '1.22.0';
  else if (model == 'Latitude 3440') fix = '1.16.0';
  else if (model == 'Latitude 3450') fix = '1.8.0';
  else if (model == 'Latitude 3500') fix = '1.35.1';
  else if (model == 'Latitude 3510') fix = '1.32.1';
  else if (model == 'Latitude 3520') fix = '1.38.0';
  else if (model == 'Latitude 3530') fix = '1.22.0';
  else if (model == 'Latitude 3540') fix = '1.16.0';
  else if (model == 'Latitude 3550') fix = '1.8.0';
  else if (model == 'Latitude 5290') fix = '1.38.0';
  else if (model == 'Latitude 5290 2-in-1') fix = '1.37.0';
  else if (model == 'Latitude 5300') fix = '1.33.1';
  else if (model == 'Latitude 5300 2-in-1') fix = '1.33.1';
  else if (model == 'Latitude 5310') fix = '1.26.1';
  else if (model == 'Latitude 5310 2-in-1') fix = '1.26.1';
  else if (model == 'Latitude 5320') fix = '1.40.0';
  else if (model == 'Latitude 5330') fix = '1.25.0';
  else if (model == 'Latitude 5340') fix = '1.16.0';
  else if (model == 'Latitude 5350') fix = '1.8.0';
  else if (model == 'Latitude 5400') fix = '1.35.0';
  else if (model == 'Latitude 5401') fix = '1.36.0';
  else if (model == 'Latitude 5410') fix = '1.33.0';
  else if (model == 'Latitude 5411') fix = '1.34.0';
  else if (model == 'Latitude 5420') fix = '1.41.0';
  else if (model == 'Latitude 5420 Rugged') fix = '1.35.0';
  else if (model == 'Latitude 5421') fix = '1.35.0';
  else if (model == 'Latitude 5424 Rugged') fix = '1.35.0';
  else if (model == 'Latitude 5430') fix = '1.25.0';
  else if (model == 'Latitude 5430 Rugged Laptop') fix = '1.31.2';
  else if (model == 'Latitude 5431') fix = '1.25.0';
  else if (model == 'Latitude 5440') fix = '1.18.1';
  else if (model == 'Latitude 5450') fix = '1.8.0';
  else if (model == 'Latitude 5480') fix = '1.39.0';
  else if (model == 'Latitude 5488') fix = '1.39.0';
  else if (model == 'Latitude 5490') fix = '1.38.0';
  else if (model == 'Latitude 5491') fix = '1.36.0';
  else if (model == 'Latitude 5495') fix = '1.17.0';
  else if (model == 'Latitude 5500') fix = '1.35.0';
  else if (model == 'Latitude 5501') fix = '1.36.0';
  else if (model == 'Latitude 5510') fix = '1.33.0';
  else if (model == 'Latitude 5511') fix = '1.34.0';
  else if (model == 'Latitude 5520') fix = '1.40.0';
  else if (model == 'Latitude 5521') fix = '1.34.0';
  else if (model == 'Latitude 5530') fix = '1.25.0';
  else if (model == 'Latitude 5531') fix = '1.26.0';
  else if (model == 'Latitude 5540') fix = '1.16.0';
  else if (model == 'Latitude 5550') fix = '1.8.0';
  else if (model == 'Latitude 5580') fix = '1.39.0';
  else if (model == 'Latitude 5590') fix = '1.38.0';
  else if (model == 'Latitude 5591') fix = '1.36.0';
  else if (model == 'Latitude 7030 Rugged Extreme') fix = '1.10.0';
  else if (model == 'Latitude 7200 2-In-1') fix = '1.33.1';
  else if (model == 'Latitude 7210 2-in-1') fix = '1.35.1';
  else if (model == 'Latitude 7212 Rugged Extreme Tablet') fix = '1.53.0';
  else if (model == 'Latitude 7220 Rugged Extreme') fix = '1.41.0';
  else if (model == 'Latitude 7230 Rugged Extreme') fix = '1.19.1';
  else if (model == 'Latitude 7280') fix = '1.40.0';
  else if (model == 'Latitude 7290') fix = '1.41.0';
  else if (model == 'Latitude 7300') fix = '1.36.0';
  else if (model == 'Latitude 7310') fix = '1.35.0';
  else if (model == 'Latitude 7320') fix = '1.38.1';
  else if (model == 'Latitude 7320 Detachable') fix = '1.35.1';
  else if (model == 'Latitude 7330') fix = '1.26.0';
  else if (model == 'Latitude 7330 Rugged Laptop') fix = '1.31.2';
  else if (model == 'Latitude 7340') fix = '1.17.0';
  else if (model == 'Latitude 7350') fix = '1.8.0';
  else if (model == 'Latitude 7350 Detachable') fix = '1.7.1';
  else if (model == 'Latitude 7380') fix = '1.40.0';
  else if (model == 'Latitude 7390') fix = '1.41.0';
  else if (model == 'Latitude 7390 2-IN-1') fix = '1.38.0';
  else if (model == 'Latitude 7400') fix = '1.36.0';
  else if (model == 'Latitude 7400 2-In-1') fix = '1.32.1';
  else if (model == 'Latitude 7410') fix = '1.35.0';
  else if (model == 'Latitude 7420') fix = '1.38.1';
  else if (model == 'Latitude 7424 Rugged Extreme') fix = '1.35.0';
  else if (model == 'Latitude 7430') fix = '1.26.0';
  else if (model == 'Latitude 7440') fix = '1.18.1';
  else if (model == 'Latitude 7450') fix = '1.8.1';
  else if (model == 'Latitude 7480') fix = '1.40.0';
  else if (model == 'Latitude 7490') fix = '1.41.0';
  else if (model == 'Latitude 7520') fix = '1.38.1';
  else if (model == 'Latitude 7530') fix = '1.26.0';
  else if (model == 'Latitude 7640') fix = '1.18.1';
  else if (model == 'Latitude 7650') fix = '1.8.1';
  else if (model == 'Latitude 9330') fix = '1.23.0';
  else if (model == 'Latitude 9410') fix = '1.34.0';
  else if (model == 'Latitude 9420') fix = '1.34.1';
  else if (model == 'Latitude 9430') fix = '1.26.0';
  else if (model == 'Latitude 9440 2-in-1') fix = '1.14.0';
  else if (model == 'Latitude 9450') fix = '1.7.1';
  else if (model == 'Latitude 9510 2in1') fix = '1.33.1';
  else if (model == 'Latitude 9520') fix = '1.36.0';
  else if (model == 'Latitude Rugged 7220EX') fix = '1.41.0';
  else if (model == 'OptiPlex 3000 Micro / OptiPlex 3000 Small Form Factor / OptiPlex 3000 Tower') fix = '1.26.0';
  else if (model == 'OptiPlex 3000 Thin Client') fix = '1.23.2';
  else if (model == 'OptiPlex 3050 All-In-One') fix = '1.35.0';
  else if (model == 'OptiPlex 3070') fix = '1.30.1';
  else if (model == 'OptiPlex 3080') fix = '2.28.1';
  else if (model == 'OptiPlex 3090') fix = '2.22.1';
  else if (model == 'OptiPlex 3090 Ultra') fix = '1.32.0';
  else if (model == 'OptiPlex 3280 All-in-One') fix = '1.35.1';
  else if (model == 'OptiPlex 5000 Micro / OptiPlex 5000 Small Form Factor / OptiPlex 5000 Tower') fix = '1.26.0';
  else if (model == 'OptiPlex 5055 A-Serial') fix = '1.14.0';
  else if (model == 'OptiPlex 5055 Ryzen APU') fix = '1.14.0';
  else if (model == 'OptiPlex 5055 Ryzen CPU') fix = '1.14.0';
  else if (model == 'OptiPlex 5070') fix = '1.30.1';
  else if (model == 'OptiPlex 5080') fix = '1.28.1';
  else if (model == 'OptiPlex 5090 Micro / OptiPlex 5090 Small Form Factor / OptiPlex 5090 Tower') fix = '1.30.0';
  else if (model == 'OptiPlex 5270 All-in-One') fix = '1.33.1';
  else if (model == 'OptiPlex 5400 All-In-One') fix = '1.1.44';
  else if (model == 'OptiPlex 5480 All-in-One') fix = '1.36.1';
  else if (model == 'OptiPlex 5490 All-In-One') fix = '1.35.0';
  else if (model == 'OptiPlex 7000 Micro / OptiPlex 7000 Small Form Factor / OptiPlex 7000 Tower / OptiPlex 7000 XE Micro') fix = '1.26.0';
  else if (model == 'OptiPlex 7070') fix = '1.30.1';
  else if (model == 'OptiPlex 7070 Ultra') fix = '1.28.1';
  else if (model == 'Optiplex 7071') fix = '1.30.0';
  else if (model == 'OptiPlex 7080') fix = '1.31.0';
  else if (model == 'OptiPlex 7090 Tower') fix = '1.30.0';
  else if (model == 'OptiPlex 7090 Ultra') fix = '1.32.0';
  else if (model == 'OptiPlex 7400 All-In-One') fix = '1.1.44';
  else if (model == 'OptiPlex 7470 All-in-One') fix = '1.33.1';
  else if (model == 'OptiPlex 7480 All-in-One') fix = '1.36.1';
  else if (model == 'OptiPlex 7490 All-In-One') fix = '1.35.0';
  else if (model == 'OptiPlex 7770 All-in-One') fix = '1.33.1';
  else if (model == 'OptiPlex 7780 All-in-One') fix = '1.36.1';
  else if (model == 'OptiPlex AIO 7420') fix = '1.8.0';
  else if (model == 'OptiPlex All-in-One 7410') fix = '1.21.0';
  else if (model == 'OptiPlex Micro 7010 / OptiPlex Micro Plus 7010') fix = '1.20.0';
  else if (model == 'OptiPlex Micro 7020') fix = '1.8.0';
  else if (model == 'OptiPlex SFF 7020') fix = '1.8.0';
  else if (model == 'OptiPlex Small Form Factor 7010 / OptiPlex Small Form Factor Plus 7010') fix = '1.20.0';
  else if (model == 'OptiPlex Tower 7010 / OptiPlex Tower Plus 7010') fix = '1.20.0';
  else if (model == 'OptiPlex Tower 7020') fix = '1.8.0';
  else if (model == 'OptiPlex XE3') fix = '1.33.0';
  else if (model == 'OptiPlex XE4 SFF') fix = '1.26.0';
  else if (model == 'OptiPlex XE4 Tower') fix = '1.26.0';
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
