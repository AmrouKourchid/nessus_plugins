#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190130);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id("CVE-2023-28063");

  script_name(english:"Dell Client BIOS DoS (DSA-2023-176)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by a denial of service
vulnerability. Due to a signed to unsigned conversion error, a local attacker with administrator privileges can cause
a denial of service condition on an affected device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-us/000214780/dsa-2023-176
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a81bfc4");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:dell:bios");
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
  if (model == 'Alienware m15 R6') fix = '1.24.0';
  else if (model == 'Alienware m15 R7') fix = '1.17.0';
  else if (model == 'ChengMing 3900') fix = '1.13.0';
  else if (model == 'ChengMing 3901') fix = '1.13.0';
  else if (model == 'ChengMing 3910') fix = '1.5.1';
  else if (model == 'ChengMing 3911') fix = '1.5.1';
  else if (model == 'ChengMing 3990') fix = '1.21.0';
  else if (model == 'ChengMing 3991') fix = '1.21.0';
  else if (model == 'Dell G15 5510') fix = '1.20.0';
  else if (model == 'Dell G15 5511') fix = '1.23.0';
  else if (model == 'Dell G15 5520') fix = '1.17.0';
  else if (model == 'G3 3500') fix = '1.26.0';
  else if (model == 'G5 5590') fix = '1.25.0';
  else if (model == 'G5 5000') fix = '1.15.0';
  else if (model == 'G7 7500') fix = '1.25.0';
  else if (model == 'G7 7590') fix = '1.25.0';
  else if (model == 'G7 7700') fix = '1.25.0';
  else if (model == 'G7 7790') fix = '1.25.0';
  else if (model == 'Inspiron 13 5320') fix = '1.12.0';
  else if (model == 'Inspiron 14 5410') fix = '2.20.0';
  else if (model == 'Inspiron 14 5418') fix = '2.20.0';
  else if (model == 'Inspiron 14 5420') fix = '1.15.0';
  else if (model == 'Inspiron 14 7420 2-in-1') fix = '1.13.0';
  else if (model == 'Inspiron 14 Plus 7420') fix = '1.14.0';
  else if (model == 'Inspiron 15 3511') fix = '1.23.0';
  else if (model == 'Inspiron 15 5510') fix = '2.20.0';
  else if (model == 'Inspiron 15 5518') fix = '2.20.0';
  else if (model == 'Inspiron 16 7620 2-in-1') fix = '1.13.0';
  else if (model == 'Inspiron 16 Plus 7620') fix = '1.14.0';
  else if (model == 'Inspiron 24 5410 All-in-One') fix = '1.13.0';
  else if (model == 'Inspiron 24 5411 All-in-One') fix = '1.13.0';
  else if (model == 'Inspiron 27 7710 All-in-One') fix = '1.13.0';
  else if (model == 'Inspiron 3020 S') fix = '1.5.1';
  else if (model == 'Inspiron 3020') fix = '1.5.1';
  else if (model == 'Inspiron 3490') fix = '1.24.0';
  else if (model == 'Inspiron 3493') fix = '1.27.0';
  else if (model == 'Inspiron 3501') fix = '1.25.0';
  else if (model == 'Inspiron 3511') fix = '1.23.0';
  else if (model == 'Inspiron 3520') fix = '1.15.0';
  else if (model == 'Inspiron 3593') fix = '1.27.0';
  else if (model == 'Inspiron 3880') fix = '1.21.0';
  else if (model == 'Inspiron 3881') fix = '1.21.0';
  else if (model == 'Inspiron 3891') fix = '1.19.0';
  else if (model == 'Inspiron 3910') fix = '1.13.0';
  else if (model == 'Inspiron 13 5300') fix = '1.22.1';
  else if (model == 'Inspiron 5301') fix = '1.27.0';
  else if (model == 'Inspiron 13 5310') fix = '2.21.0';
  else if (model == 'Inspiron 5391') fix = '1.23.0';
  else if (model == 'Inspiron 5400') fix = '1.20.0';
  else if (model == 'Inspiron 5400 AIO') fix = '1.20.0';
  else if (model == 'Inspiron 5400 2in1') fix = '1.23.0';
  else if (model == 'Inspiron 5401') fix = '1.23.0';
  else if (model == 'Inspiron 5401 AIO') fix = '1.20.0';
  else if (model == 'Inspiron 5402') fix = '1.24.0';
  else if (model == 'Inspiron 5406 2in1') fix = '1.24.0';
  else if (model == 'Inspiron 5408') fix = '1.23.0';
  else if (model == 'Inspiron 5409') fix = '1.24.0';
  else if (model == 'Inspiron 5410') fix = '2.20.0';
  else if (model == 'Inspiron 5490') fix = '1.24.0';
  else if (model == 'Inspiron 5491 2in1') fix = '1.20.0';
  else if (model == 'Inspiron 5498') fix = '1.24.0';
  else if (model == 'Inspiron 15 5501') fix = '1.23.0';
  else if (model == 'Inspiron 5502') fix = '1.24.0';
  else if (model == 'Inspiron 5508') fix = '1.23.0';
  else if (model == 'Inspiron 5509') fix = '1.24.0';
  else if (model == 'Inspiron 5590') fix = '1.24.0';
  else if (model == 'Inspiron 5591 2in1') fix = '1.20.0';
  else if (model == 'Inspiron 5598') fix = '1.24.0';
  else if (model == 'Inspiron 5620') fix = '1.15.0';
  else if (model == 'Inspiron 7000') fix = '1.23.0';
  else if (model == 'Inspiron 7300 2in1') fix = '1.19.0';
  else if (model == 'Inspiron 7306 2in1') fix = '1.24.0';
  else if (model == 'Inspiron 7391') fix = '1.21.0';
  else if (model == 'Inspiron 7400') fix = '1.27.0';
  else if (model == 'Inspiron 7490') fix = '1.21.0';
  else if (model == 'Inspiron 7500') fix = '1.24.0';
  else if (model == 'Inspiron 7500 2in1 Black') fix = '1.19.0';
  else if (model == 'Inspiron 7501') fix = '1.24.0';
  else if (model == 'Inspiron 7506 2in1') fix = '1.24.0';
  else if (model == 'Inspiron 7510') fix = '1.17.0';
  else if (model == 'Inspiron 7590') fix = '1.20.0';
  else if (model == 'Inspiron 7591') fix = '1.20.0';
  else if (model == 'Inspiron 7610') fix = '1.17.0';
  else if (model == 'Inspiron 7700 AIO') fix = '1.20.0';
  else if (model == 'Inspiron 7791') fix = '1.21.0';
  else if (model == 'Latitude 3120') fix = '1.18.0';
  else if (model == 'Latitude 3140') fix = '1.7.0';
  else if (model == 'Latitude 3190 2-in-1') fix = '1.28.0';
  else if (model == 'Latitude 3300') fix = '1.22.0';
  else if (model == 'Latitude 3310') fix = '1.21.0';
  else if (model == 'Latitude 3310 2-in-1') fix = '1.20.0';
  else if (model == 'Latitude 3320') fix = '1.23.0';
  else if (model == 'Latitude 3330') fix = '1.14.0';
  else if (model == 'Latitude 3400') fix = '1.29.0';
  else if (model == 'Latitude 3410') fix = '1.25.0';
  else if (model == 'Latitude 3420') fix = '1.30.0';
  else if (model == 'Latitude 3430') fix = '1.11.0';
  else if (model == 'Latitude 3500') fix = '1.29.0';
  else if (model == 'Latitude 3510') fix = '1.25.0';
  else if (model == 'Latitude 3520') fix = '1.30.0';
  else if (model == 'Latitude 3530') fix = '1.11.0';
  else if (model == 'Latitude 5290') fix = '1.29.0';
  else if (model == 'Latitude 5290 2-in-1') fix = '1.28.0';
  else if (model == 'Latitude 5300') fix = '1.27.0';
  else if (model == 'Latitude 5300 2-in-1') fix = '1.27.0';
  else if (model == 'Latitude 5310') fix = '1.20.0';
  else if (model == 'Latitude 5310 2-in-1') fix = '1.20.0';
  else if (model == 'Latitude 5320') fix = '1.29.0';
  else if (model == 'Latitude 5330') fix = '1.13.1';
  else if (model == 'Latitude 5400') fix = '1.25.0';
  else if (model == 'Latitude 5401') fix = '1.26.0';
  else if (model == 'Latitude 5410') fix = '1.22.0';
  else if (model == 'Latitude 5411') fix = '1.23.0';
  else if (model == 'Latitude 5420') fix = '1.29.0';
  else if (model == 'Latitude 5420 Rugged') fix = '1.26.1';
  else if (model == 'Latitude 5424 Rugged') fix = '1.26.1';
  else if (model == 'Latitude 5430') fix = '1.14.0';
  else if (model == 'Latitude 5431') fix = '1.14.0';
  else if (model == 'Latitude 5490') fix = '1.29.0';
  else if (model == 'Latitude 5491') fix = '1.28.0';
  else if (model == 'Latitude 5495') fix = '1.12.0';
  else if (model == 'Latitude 5500') fix = '1.25.0';
  else if (model == 'Latitude 5501') fix = '1.26.0';
  else if (model == 'Latitude 5510') fix = '1.22.0';
  else if (model == 'Latitude 5511') fix = '1.23.0';
  else if (model == 'Latitude 5520') fix = '1.29.0';
  else if (model == 'Latitude 5521') fix = '1.23.0';
  else if (model == 'Latitude 5530') fix = '1.13.2';
  else if (model == 'Latitude 5531') fix = '1.14.1';
  else if (model == 'Latitude 5590') fix = '1.29.0';
  else if (model == 'Latitude 5591') fix = '1.28.0';
  else if (model == 'Latitude 7200 2-in-1') fix = '1.23.0';
  else if (model == 'Latitude 7210 2-in-1') fix = '1.23.0';
  else if (model == 'Latitude 7230 Rugged Extreme Tablet') fix = '1.7.0';
  else if (model == 'Latitude 7290') fix = '1.33.0';
  else if (model == 'Latitude 7300') fix = '1.26.0';
  else if (model == 'Latitude 7310') fix = '1.24.0';
  else if (model == 'Latitude 7320') fix = '1.27.0';
  else if (model == 'Latitude 7320 Detachable') fix = '1.23.0';
  else if (model == 'Latitude 7330') fix = '1.15.0';
  else if (model == 'Latitude 7390') fix = '1.33.0';
  else if (model == 'Latitude 7390 2-in-1') fix = '1.31.0';
  else if (model == 'Latitude 7400') fix = '1.26.0';
  else if (model == 'Latitude 7400 2-in-1') fix = '1.22.0';
  else if (model == 'Latitude 7410') fix = '1.24.0';
  else if (model == 'Latitude 7420') fix = '1.27.0';
  else if (model == 'Latitude 7424 Rugged Extreme') fix = '1.26.1';
  else if (model == 'Latitude 7430') fix = '1.15.0';
  else if (model == 'Latitude 7490') fix = '1.33.0';
  else if (model == 'Latitude 7520') fix = '1.27.0';
  else if (model == 'Latitude 7530') fix = '1.15.0';
  else if (model == 'Latitude 9330') fix = '1.12.1';
  else if (model == 'Latitude 9410') fix = '1.23.0';
  else if (model == 'Latitude 9420') fix = '1.22.0';
  else if (model == 'Latitude 9430') fix = '1.15.0';
  else if (model == 'Latitude 9510') fix = '1.21.0';
  else if (model == 'Latitude 9520') fix = '1.23.0';
  else if (model == 'Latitude 5430 Rugged') fix = '1.18.1';
  else if (model == 'Latitude 7220 Rugged') fix = '1.29.0';
  else if (model == 'Latitude 7220EX Rugged') fix = '1.29.0';
  else if (model == 'Latitude 7330 Rugged') fix = '1.18.1';
  else if (model == 'Latitude 5421') fix = '1.22.0';
  else if (model == 'OptiPlex 3000') fix = '1.13.1';
  else if (model == 'OptiPlex 3000 Micro') fix = '1.13.1';
  else if (model == 'OptiPlex 3000 Small Form Factor') fix = '1.13.1';
  else if (model == 'OptiPlex 3000 Tower') fix = '1.13.1';
  else if (model == 'OptiPlex 3000 Thin Client') fix = '1.10.0';
  else if (model == 'OptiPlex 3080') fix = '2.20.0';
  else if (model == 'OptiPlex 3090') fix = '2.14.0';
  else if (model == 'OptiPlex 3090 UFF') fix = '1.21.0';
  else if (model == 'OptiPlex 3280 AIO') fix = '1.22.0';
  else if (model == 'OptiPlex 5000') fix = '1.13.1';
  else if (model == 'OptiPlex 5000 Micro') fix = '1.13.1';
  else if (model == 'OptiPlex 5000 Small Form Factor') fix = '1.13.1';
  else if (model == 'Optiplex 5000 Tower') fix = '1.13.1';
  else if (model == 'OptiPlex 5080') fix = '1.20.0';
  else if (model == 'OptiPlex 5090') fix = '1.19.0';
  else if (model == 'OptiPlex 5090 Micro') fix = '1.19.0';
  else if (model == 'OptiPlex 5090 Small Form Factor') fix = '1.19.0';
  else if (model == 'OptiPlex 5090 Tower') fix = '1.19.0';
  else if (model == 'OptiPlex 5400 AIO') fix = '1.1.28';
  else if (model == 'OptiPlex 5480 AIO') fix = '1.23.0';
  else if (model == 'OptiPlex 5490 AIO') fix = '1.22.0';
  else if (model == 'OptiPlex 7000') fix = '1.13.1';
  else if (model == 'OptiPlex 7000 Micro') fix = '1.13.1';
  else if (model == 'OptiPlex 7000 Small Form Factor') fix = '1.13.1';
  else if (model == 'OptiPlex 7000 Tower') fix = '1.13.1';
  else if (model == 'OptiPlex 7000 XE Micro') fix = '1.13.1';
  else if (model == 'OptiPlex 7080') fix = '1.21.0';
  else if (model == 'OptiPlex 7090') fix = '1.19.0';
  else if (model == 'OptiPlex 7090 UFF') fix = '1.21.0';
  else if (model == 'OptiPlex 7400 AIO') fix = '1.1.28';
  else if (model == 'OptiPlex 7480 AIO') fix = '1.23.0';
  else if (model == 'OptiPlex 7490 AIO') fix = '1.22.0';
  else if (model == 'OptiPlex 7780 AIO') fix = '1.23.0';
  else if (model == 'OptiPlex AIO 7410 35W') fix = '1.4.1';
  else if (model == 'OptiPlex AIO 7410 65W') fix = '1.4.1';
  else if (model == 'OptiPlex Micro 7010') fix = '1.5.1';
  else if (model == 'OptiPlex Micro Plus 7010') fix = '1.5.1';
  else if (model == 'OptiPlex SFF 7010') fix = '1.5.1';
  else if (model == 'OptiPlex SFF Plus 7010') fix = '1.5.1';
  else if (model == 'OptiPlex Tower 7010') fix = '1.5.1';
  else if (model == 'OptiPlex Tower Plus 7010') fix = '1.5.1';
  else if (model == 'OptiPlex XE4 Series') fix = '1.13.1';
  else if (model == 'OptiPlex XE4 OEM-Ready') fix = '1.13.1';
  else if (model == 'Precision 3260 XE Compact') fix = '2.5.1';
  else if (model == 'Precision 3260 Compact') fix = '2.5.1';
  else if (model == 'Precision 3440') fix = '1.21.0';
  else if (model == 'Precision 3450') fix = '1.19.0';
  else if (model == 'Precision 3460') fix = '2.4.0';
  else if (model == 'Precision 3460 XE Small Form Factor') fix = '2.4.0';
  else if (model == 'Precision 3460 Small Form Factor') fix = '2.4.0';
  else if (model == 'Precision 3470') fix = '1.14.0';
  else if (model == 'Precision 3530') fix = '1.28.0';
  else if (model == 'Precision 3540') fix = '1.25.0';
  else if (model == 'Precision 3541') fix = '1.26.0';
  else if (model == 'Precision 3550') fix = '1.22.0';
  else if (model == 'Precision 3551') fix = '1.23.0';
  else if (model == 'Precision 3560') fix = '1.29.0';
  else if (model == 'Precision 3561') fix = '1.23.0';
  else if (model == 'Precision 3570') fix = '1.13.2';
  else if (model == 'Precision 3571') fix = '1.14.1';
  else if (model == 'Precision 3640 Tower') fix = '1.23.0';
  else if (model == 'Precision 3650 Tower') fix = '1.23.0';
  else if (model == 'Precision 3660') fix = '2.6.1';
  else if (model == 'Precision 5470') fix = '1.14.0';
  else if (model == 'Precision 5530 2-in-1') fix = '1.26.8';
  else if (model == 'Precision 5550') fix = '1.24.1';
  else if (model == 'Precision 5560') fix = '1.22.0';
  else if (model == 'Precision 5570') fix = '1.15.0';
  else if (model == 'Precision 5750') fix = '1.26.1';
  else if (model == 'Precision 5760') fix = '1.21.0';
  else if (model == 'Precision 5770') fix = '1.17.1';
  else if (model == 'Precision 7530') fix = '1.29.1';
  else if (model == 'Precision 7540') fix = '1.27.0';
  else if (model == 'Precision 7550') fix = '1.25.0';
  else if (model == 'Precision 7560') fix = '1.23.0';
  else if (model == 'Precision 7670') fix = '1.13.0';
  else if (model == 'Precision 7730') fix = '1.29.1';
  else if (model == 'Precision 7740') fix = '1.27.0';
  else if (model == 'Precision 7750') fix = '1.25.0';
  else if (model == 'Precision 7760') fix = '1.23.0';
  else if (model == 'Precision 7770') fix = '1.13.0';
  else if (model == 'Precision 7865 Tower') fix = '1.1.0';
  else if (model == 'Vostro 3020 SFF') fix = '1.5.1';
  else if (model == 'Vostro 3020 T') fix = '1.5.1';
  else if (model == 'Vostro 3400') fix = '1.25.0';
  else if (model == 'Vostro 3420') fix = '1.15.0';
  else if (model == 'Vostro 3500') fix = '1.25.0';
  else if (model == 'Vostro 3510') fix = '1.23.0';
  else if (model == 'Vostro 3520') fix = '1.15.0';
  else if (model == 'Vostro 3590') fix = '1.24.0';
  else if (model == 'Vostro 3681') fix = '2.21.0';
  else if (model == 'Vostro 3690') fix = '1.19.0';
  else if (model == 'Vostro 3710') fix = '1.13.0';
  else if (model == 'Vostro 3881') fix = '2.21.0';
  else if (model == 'Vostro 3890') fix = '1.19.0';
  else if (model == 'Vostro 3910') fix = '1.13.0';
  else if (model == 'Vostro 5300') fix = '1.22.1';
  else if (model == 'Vostro 5301') fix = '1.27.0';
  else if (model == 'Vostro 5310') fix = '2.21.0';
  else if (model == 'Vostro 5320') fix = '1.12.0';
  else if (model == 'Vostro 5391') fix = '1.23.0';
  else if (model == 'Vostro 5401') fix = '1.23.0';
  else if (model == 'Vostro 5402') fix = '1.24.0';
  else if (model == 'Vostro 5410') fix = '2.20.0';
  else if (model == 'Vostro 5490') fix = '1.24.0';
  else if (model == 'Vostro 5501') fix = '1.23.0';
  else if (model == 'Vostro 5502') fix = '1.24.0';
  else if (model == 'Vostro 5510') fix = '2.20.0';
  else if (model == 'Vostro 5590') fix = '1.24.0';
  else if (model == 'Vostro 5591') fix = '1.27.0';
  else if (model == 'Vostro 5620') fix = '1.15.0';
  else if (model == 'Vostro 5880') fix = '1.21.0';
  else if (model == 'Vostro 5890') fix = '1.19.0';
  else if (model == 'Vostro 7500') fix = '1.24.0';
  else if (model == 'Vostro 7510') fix = '1.17.0';
  else if (model == 'Vostro 7590') fix = '1.20.0';
  else if (model == 'Vostro 7620') fix = '1.14.0';
  else if (model == 'XPS 13 9305') fix = '1.16.0';
  else if (model == 'XPS 13 7390') fix = '1.21.0';
  else if (model == 'XPS 13 7390 2-in-1') fix = '1.26.0';
  else if (model == 'XPS 13 9300') fix = '1.19.0';
  else if (model == 'XPS 13 9310') fix = '3.17.0';
  else if (model == 'XPS 13 9310 2-in-1') fix = '2.19.0';
  else if (model == 'XPS 13 9315') fix = '1.12.0';
  else if (model == 'XPS 13 9315 2-in-1') fix = '1.8.1';
  else if (model == 'XPS 13 9380') fix = '1.25.0';
  else if (model == 'XPS 13 Plus 9320') fix = '2.4.0';
  else if (model == 'XPS 15 7590') fix = '1.23.0';
  else if (model == 'XPS 15 9500') fix = '1.24.1';
  else if (model == 'XPS 15 9510') fix = '1.22.0';
  else if (model == 'XPS 15 9520') fix = '1.15.0';
  else if (model == 'XPS 15 9575') fix = '1.28.0';
  else if (model == 'XPS 17 9700') fix = '1.26.1';
  else if (model == 'XPS 17 9710') fix = '1.21.0';
  else if (model == 'XPS 17 9720') fix = '1.17.1';
  else if (model == 'XPS 8940') fix = '2.14.0';
  # Extra products for different Tower/Rack orderings
  else if (model == 'OptiPlex Tower 3000') fix = '1.13.1';
  else if (model == 'Optiplex Tower 5000') fix = '1.13.1';
  else if (model == 'OptiPlex Tower 5090') fix = '1.19.0';
  else if (model == 'OptiPlex Tower 7000') fix = '1.13.1';
  else if (model == 'Precision Tower 3640') fix = '1.23.0';
  else if (model == 'Precision Tower 3650') fix = '1.23.0';
  else if (model == 'Precision Tower 7865') fix = '1.1.0';
  else if (model == 'Vostro Tower 3020') fix = '1.5.1';
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
