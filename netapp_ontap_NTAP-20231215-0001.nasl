#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187381);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/29");

  script_cve_id("CVE-2023-27317");
  script_xref(name:"IAVB", value:"2023-B-0102");

  script_name(english:"NetApp ONTAP 9.12.1P8 /  9.13.1P4 / 9.13.1P5 Information Disclosure (NTAP-20231215-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of NetApp ONTAP running on the remote host is 9.12.1P8, 9.13.1P4 or 9.13.1P5. It ts, therefore, affected
by an information disclosure vulnerability as detailed in the NTAP-20231215-0001 advisory. All SAS-attached FIPS 140-2
drives become unlocked after a system reboot or power cycle and a single SAS-attached FIPS 140-2 drive becomes unlocked
after reinsertion. This results in disclosure of sensitive information to an attacker with physical access to the
unlocked drives.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.netapp.com/advisory/NTAP-20231215-0001/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetApp ONTAP version 9.12.1P9, 9.13.1P6, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27317");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:netapp:data_ontap");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_ontap_detect.nbin");
  script_require_keys("Host/NetApp/ONTAP/display_version");

  exit(0);
}

include('vcf.inc');

var app_name = 'NetApp ONTAP';

var app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/NetApp/ONTAP/display_version');

var constraints = [
  { 'equal': '9.12.1P8', 'fixed_display':'9.12.1P9' },
  { 'equal': '9.13.1P4', 'fixed_display':'9.13.1P6' },
  { 'equal': '9.13.1P5', 'fixed_display':'9.13.1P6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
