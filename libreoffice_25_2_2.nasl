#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235031);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id("CVE-2025-2866");
  script_xref(name:"IAVB", value:"2025-B-0063");

  script_name(english:"LibreOffice 24.8.x < 24.8.6 / 25.2.x < 25.2.2 (CVE-2025-2866)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote host is prior to 24.8.6 or 25.2.2. It is, therefore, affected by a
PDF signature spoofing vulnerability:

  - Improper Verification of Cryptographic Signature vulnerability in LibreOffice allows PDF Signature Spoofing by
    Improper Validation. In the affected versions of LibreOffice a flaw in the verification code for adbe.pkcs7.sha1
    signatures could cause invalid signatures to be accepted as valid This issue affects LibreOffice: from 24.8 before
    < 24.8.6, from 25.2 before < 25.2.2.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2025-2866");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 24.8.6 or 25.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2866");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl", "macosx_libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'LibreOffice', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version':'24.8.0', 'fixed_version': '24.8.6'},
        {'min_version':'25.2.0', 'fixed_version': '25.2.2'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
