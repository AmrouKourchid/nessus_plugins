#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234891);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id("CVE-2025-32414", "CVE-2025-32415");
  script_xref(name:"IAVA", value:"2025-A-0229-S");
  script_xref(name:"IAVA", value:"2025-A-0293");

  script_name(english:"libxml2 < 2.13.8 / 2.14.x < 2.14.2 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of libxml2 installed on the remote host is affected by multiple vulnerabilities.

  - In libxml2 before 2.13.8 and 2.14.x before 2.14.2, out-of-bounds memory access can occur in the Python
    API (Python bindings) because of an incorrect return value. This occurs in xmlPythonFileRead and
    xmlPythonFileReadRaw because of a difference between bytes and characters. (CVE-2025-32414)

  - In libxml2 before 2.13.8 and 2.14.x before 2.14.2, xmlSchemaIDCFillNodeTables in xmlschemas.c has a
    heap-based buffer under-read. To exploit this, a crafted XML document must be validated against an XML
    schema with certain identity constraints, or a crafted XML schema must be used. (CVE-2025-32415)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.gnome.org/GNOME/libxml2/-/issues/889");
  script_set_attribute(attribute:"see_also", value:"https://gitlab.gnome.org/GNOME/libxml2/-/issues/890");
  script_set_attribute(attribute:"solution", value:
"Upgrade to libxml2 version 2.13.8, 2.14.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32414");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xmlsoft:libxml2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_libxml2_installed.nbin");
  script_require_keys("installed_sw/libxml2", "Host/MacOSX/Version");

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
      'product': {'name': 'libxml2', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'fixed_version' : '2.13.8' },
        { 'min_version' : '2.14.0', 'fixed_version' : '2.14.2' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
