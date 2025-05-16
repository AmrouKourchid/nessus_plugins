#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76333);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/02");

  script_xref(name:"IAVA", value:"0001-A-0533");

  script_name(english:"F5 Networks ARX Data Manager Unsupported Version Detection");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a file management
platform.");
  script_set_attribute(attribute:"description", value:
"The remote host is running F5 Networks ARX Data Manager. According to
the vendor, this product is no longer supported and security fixes
will not be released. As a result, it is likely to contain security
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K14777");
  script_set_attribute(attribute:"see_also", value:"https://my.f5.com/manage/s/article/K8466");
  script_set_attribute(attribute:"solution", value:"Contact the vendor or migrate to a different product.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/01");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable standard unsupported software score.");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:arx_data_manager");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("f5_data_manager_detect.nbin");
  script_require_keys("installed_sw/F5 Networks ARX Data Manager");

  exit(0);
}


include('ucf.inc');

var app = 'F5 Networks ARX Data Manager';

var app_info = vcf::combined_get_app_info(app:app);

vcf::check_all_backporting(app_info:app_info);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { branch : '2.4', seol : 20090205 },
  { branch : '2.5', seol : 20090205 },
  { branch : '2.6', seol : 20090212 },
  { branch : '2.7', seol : 20111121 },
  { branch : '3', seol : 20111221 },
  { branch : '4', seol : 20120617 },
  { branch : '5.0', seol : 20131118 },
  { branch : '5.1', seol : 20140101 },
  { branch : '5.2', seol : 20140801 },
  { branch : '5.3.0', seol : 20120628 },
  { branch : '5.3.1', seol : 20140801 },
  { branch : '6.0.0', seol : 20130913 },
  { branch : '6.1.0', seol : 20140118 },
  { branch : '6.2.0', seol : 20181101 },
  { branch : '6.3.0', seol : 20181101 },
  { branch : '6.4.0', seol : 20181101 }
];

ucf::check_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
