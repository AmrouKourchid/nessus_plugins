#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234215);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2024-6376");
  script_xref(name:"IAVB", value:"2025-B-0054");

  script_name(english:"MongoDB Compass < 1.42.2 Code Injection (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of MongoDB Compass installed on the remote host is affected by a code injection vulnerability. MongoDB
Compass may be susceptible to code injection due to insufficient sandbox protection settings with the usage of ejson
shell parser in Compass' connection handling. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/COMPASS-7496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB Compass version 1.42.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6376");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:compass");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_mongodb_compass_installed.nbin");
  script_require_keys("installed_sw/MongoDB Compass", "Host/MacOSX/Version");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'macos'}}
  ],
  'checks': [
    {
      'product': {'name': 'MongoDB Compass', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'fixed_version' : '1.42.2' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
