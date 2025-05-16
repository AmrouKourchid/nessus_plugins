#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180189);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id("CVE-2023-32453");
  script_xref(name:"IAVA", value:"2023-A-0437");

  script_name(english:"Dell Client BIOS Improper Authentication (DSA-2023-190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The Dell BIOS on the remote device is missing a security patch and is, therefore, affected by a improper 
authentication vulnerability.A malicious user with physical access to the system may potentially exploit 
this vulnerability in order to modify a security-critical UEFI variable without knowledge of the BIOS 
administrator.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000215217/dsa-2023-190-security-update-for-a-dell-client-bios-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2ab73ee");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32453");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/25");

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
  if (model == 'Alienware m15 R7') fix = '1.18.0';
  else if (model == 'Alienware m16') fix = '1.10.1';
  else if (model == 'Alienware m18') fix = '1.10.1';
  else if (model == 'ChengMing 3900') fix = '1.15.0';
  else if (model == 'ChengMing 3901') fix = '1.15.0';
  else if (model == 'ChengMing 3910') fix = '1.6.0';
  else if (model == 'ChengMing 3911') fix = '1.6.0';
  else if (model =~ 'G15 5520') fix = '1.18.0';
  else if (model =~ 'G16 7620') fix = '1.18.0';
  else if (model =~ 'G3 3500') fix = '1.26.0';
  else if (model =~ 'G5( 15)? 5500') fix = '1.26.0';
  else if (model =~ 'G7( 15)? 7500') fix = '1.26.0';
  else if (model =~ 'G7( 17)? 7700') fix = '1.26.0';
  else if (model == 'Precision 5680') fix = '1.4.1';
  else if (model == 'Inspiron 14 5410') fix = '2.20.0';
  else if (model == 'Inspiron 14 5418') fix = '2.20.0';
  else if (model == 'Inspiron 15 3511') fix = '1.23.0';
  else if (model == 'Inspiron 15 5510') fix = '2.20.0';
  else if (model == 'Inspiron 15 5518') fix = '2.20.0';
  else if (model == 'Inspiron 24 5420 AIO') fix = '1.4.0'; 
  else if (model == 'Inspiron 24 5421 AIO') fix = '1.4.0';
  else if (model == 'Inspiron 27 7720 AIO') fix = '1.4.0';
  else if (model == 'Inspiron 3020 Small Desktop') fix = '1.6.0';
  else if (model == 'Inspiron 3020 Desktop') fix = '1.6.0';
  else if (model == 'Inspiron 3493') fix = '1.27.0';
  else if (model == 'Inspiron 3511') fix = '1.23.0';
  else if (model == 'Inspiron 3593') fix = '1.27.0';
  else if (model == 'Inspiron 3793') fix = '1.27.0';
  else if (model == 'Inspiron 3891') fix = '1.19.0';
  else if (model == 'Inspiron 3910') fix = '1.15.0';
  else if (model == 'Inspiron 5410') fix = '2.20.0';
  else if (model == 'Inspiron 5493') fix = '1.27.0';
  else if (model == 'Inspiron 5593') fix = '1.27.0';
  else if (model == 'Inspiron 7300 2-in-1') fix = '1.19.0';
  else if (model == 'Inspiron 7490') fix = '1.22.0';
  else if (model == 'Inspiron 7500') fix = '1.24.0';
  else if (model == 'Inspiron 7500 2-in-1 Black') fix = '1.19.0';
  else if (model == 'Inspiron 7501') fix = '1.24.0';
  else if (model == 'Inspiron 7510') fix = '1.17.0';
  else if (model == 'Inspiron 7610') fix = '1.17.0';
  else if (model == 'Latitude 3140') fix = '1.8.0';
  else if (model == 'Latitude 3301') fix = '1.27.0';
  else if (model == 'Latitude 3320') fix = '1.23.0';
  else if (model == 'Latitude 3330') fix = '1.15.0';
  else if (model == 'Latitude 3340') fix = '1.6.0';
  else if (model == 'Latitude 3400') fix = '1.29.0';
  else if (model == 'Latitude 3430') fix = '1.12.0';
  else if (model == 'Latitude 3440') fix = '1.6.0';
  else if (model == 'Latitude 3500') fix = '1.29.0';
  else if (model == 'Latitude 3530') fix = '1.12.0';
  else if (model == 'Latitude 3540') fix = '1.6.0';
  else if (model == 'Latitude 5420') fix = '1.30.0';
  else if (model == 'Latitude 5430') fix = '1.15.0';
  else if (model == 'Latitude 5431') fix = '1.15.0';
  else if (model == 'Latitude 7230 Rugged Extreme Tablet') fix = '1.8.0';
  else if (model == 'Latitude 7320') fix = '1.28.0';
  else if (model == 'Latitude 7420') fix = '1.28.0';
  else if (model == 'Latitude 7520') fix = '1.28.0';
  else if (model == 'Latitude 9330') fix = '1.13.0';
  else if (model == 'Latitude 9520') fix = '1.24.0';
  else if (model == 'Latitude Rugged 5430') fix = '1.20.0';
  else if (model == 'Latitude Rugged 7330') fix = '1.20.0';
  else if (model == 'OptiPlex 3000') fix = '1.15.0';
  else if (model == 'OptiPlex 3000 Thin Client') fix = '1.11.0';
  else if (model == 'OptiPlex 5000') fix = '1.15.0';
  else if (model == 'OptiPlex 5090') fix = '1.19.0';
  else if (model == 'OptiPlex 5400 AIO') fix = '1.1.30';
  else if (model == 'OptiPlex 5490 AIO') fix = '1.23.0';
  else if (model == 'OptiPlex 7000') fix = '1.15.0'; 
  else if (model == 'OptiPlex 7000 Tower') fix = '1.15.0'; 
  else if (model == 'OptiPlex 7000 XE Micro') fix = '1.15.0';
  else if (model == 'OptiPlex 7090') fix = '1.19.0';
  else if (model == 'OptiPlex 7400 AIO') fix = '1.1.30';
  else if (model == 'OptiPlex 7490 AIO') fix = '1.23.0';
  else if (model == 'OptiPlex AIO 7410') fix = '1.6.0';
  else if (model == 'OptiPlex Plus 7010') fix = '1.6.0';
  else if (model == 'OptiPlex Tower Plus 7010') fix = '1.6.0';
  else if (model == 'OptiPlex XE4') fix = '1.15.0'; 
  else if (model == 'OptiPlex XE4 OEM-Ready') fix = '1.15.0';
  else if (model == 'Precision 3260 XE Compact') fix = '2.7.0'; 
  else if (model == 'Precision 3260 Compact') fix = '2.7.0';
  else if (model == 'Precision 3450') fix = '1.19.0';
  else if (model == 'Precision 3460 XE Small Form Factor') fix = '2.7.0'; 
  else if (model == 'Precision 3460 Small Form Factor') fix = '2.7.0';
  else if (model == 'Precision 3470') fix = '1.15.0';
  else if (model == 'Precision 3650 Tower') fix = '1.24.0';
  else if (model == 'Precision 3660') fix = '2.7.0';
  else if (model == 'Precision 5470') fix = '1.15.0';
  else if (model == 'Precision 5570') fix = '1.16.0';
  else if (model == 'Precision 5860 Tower') fix = '1.0.10';
  else if (model == 'Precision 7960 Tower') fix = '1.0.9';
  else if (model == 'Vostro 3020 SFF') fix = '1.6.0';
  else if (model == 'Vostro 3020 T') fix = '1.6.0';
  else if (model == 'Vostro 3510') fix = '1.23.0';
  else if (model == 'Vostro 3690') fix = '1.19.0';
  else if (model == 'Vostro 3710') fix = '1.15.0';
  else if (model == 'Vostro 3890') fix = '1.19.0';
  else if (model == 'Vostro 3910') fix = '1.15.0';
  else if (model == 'Vostro 5410') fix = '2.20.0';
  else if (model == 'Vostro 5491') fix = '1.27.0';
  else if (model == 'Vostro 5510') fix = '2.20.0';
  else if (model == 'Vostro 5591') fix = '1.27.0';
  else if (model == 'Vostro 5890') fix = '1.19.0';
  else if (model == 'Vostro 7500') fix = '1.24.0';
  else if (model == 'Vostro 7510') fix = '1.17.0';
  else if (model == 'XPS 13 9305') fix = '1.16.0';
  else if (model == 'XPS 13 7390') fix = '1.21.0';
  else if (model == 'XPS 13 7390 2-in-1') fix = '1.26.0';
  else if (model == 'XPS 13 9300') fix = '1.19.0';
  else if (model == 'XPS 13 9310') fix = '3.17.0';
  else if (model == 'XPS 13 9310 2-in-1') fix = '2.19.0';
  else if (model == 'XPS 13 9315') fix = '1.13.0';
  else if (model == 'XPS 15 9520') fix = '1.16.0';
  # Extra products for different Tower/Rack orderings
  else if (model == 'OptiPlex 3000 Tower') fix = '1.15.0';
  else if (model == 'OptiPlex 5000 Tower') fix = '1.15.0';
  else if (model == 'OptiPlex 5090 Tower') fix = '1.19.0';
  else if (model == 'Precision Tower 3650') fix = '1.24.0';
  else if (model == 'Precision Tower 5860') fix = '1.0.10';
  else if (model == 'Precision Tower 7960') fix = '1.0.9';
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