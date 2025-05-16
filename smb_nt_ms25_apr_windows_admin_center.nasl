#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234219);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id("CVE-2025-29819");
  script_xref(name:"IAVA", value:"2025-A-0239");

  script_name(english:"Microsoft Windows Admin Center Information Disclosure (April 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is contains an application that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Windows Admin Center that is missing a security update. It is,
therefore, affected by an information disclosure vulnerability. An attacker can exploit this to disclose potentially sensitive
information. (CVE-2025-29819)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-29819");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29819");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_admin_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windows_admin_center_installed.nbin");
  script_require_keys("installed_sw/Windows Admin Center");

  exit(0);
}

include('vdf.inc');

var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target'}],
  'checks': [
    {
      'product':{'name': 'Windows Admin Center', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'fixed_version': '2.4.2.1'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);