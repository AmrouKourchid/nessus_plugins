#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234190);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-31672");
  script_xref(name:"IAVB", value:"2025-B-0052");

  script_name(english:"Apache POI < 5.4.0 Improper Input Validation");

  script_set_attribute(attribute:"synopsis", value:
"The version of Apache POI installed on the remote host is affected by an improper input validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache POI installed on the remote host is a version prior to 5.4.0. It is, therefore, affected by an 
improper input validation vulnerability. The issue affects the parsing of OOXML format files like xlsx, docx, and pptx. 
These file formats are essentially zip files, and it is possible for malicious users to add zip entries with duplicate 
names (including the path) in the zip. In such cases, products reading the affected file could read different data 
because one of the zip entries with the duplicate name is selected over another, but different products may choose a 
different zip entry. This issue affects Apache POI poi-ooxml before 5.4.0. Version 5.4.0 introduces a check that throws 
an exception if zip entries with duplicate file names are found in the input file.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/k14w8vcjqy4h34hh5kzldko78kpylkq5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache POI 5.4.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-31672");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:poi");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_poi_detect.nbin");
  script_require_keys("installed_sw/Apache POI");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = { 
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {   
      'product': {'name': 'Apache POI', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
            'fixed_version': '5.4.0'
        }
      ]   
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);   