#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233463);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2025-2499", 
    "CVE-2025-2528", 
    "CVE-2025-2562", 
    "CVE-2025-2600"
    );
  script_xref(name:"IAVB", value:"2025-B-0044");

  script_name(english:"Devolutions Remote Desktop < 2024.3.31 / 2025.x < 2025.1.26 multiple vulnerabilities (DEVO-2025-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Remote Desktop Manager instance installed on the remote host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Devolutions Remote Desktop Manager installed on the remote host is prior to 2024.3.31 / 2025.1.26 and is,
therefore, affected by multiple vulnerabilities:

  - Client side access control bypass in the permission component in Devolutions Remote Desktop Manager on Windows.
    An authenticated user can exploit this flaw to bypass certain permission restrictions—specifically View Password, 
    Edit Asset, and Edit Permissions by performing specific actions. (CVE-2025-2499)

  - Improper authorization in application password policy in Devolutions Remote Desktop Manager on Windows allows an 
    authenticated user to use a configuration different from the one mandated by the 
    system administrators. (CVE-2025-2528)

  - Insufficient logging in the autotyping feature in Devolutions Remote Desktop Manager on Windows allows an 
    authenticated user to use a stored password without generating a corresponding log event, via the use of the 
    autotyping functionality. (CVE-2025-2562)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2025-0005");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Remote Desktop Manager version 2024.3.31 / 2025.1.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2499");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_desktop_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_desktop_manager_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Remote Desktop Manager", "SMB/Registry/Enumerated");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [{'scope': 'target', 'match': {'os': 'windows'}}],
  'checks': [
    {
      'check_algorithm': 'default',
      'product': {'name': 'Devolutions Remote Desktop Manager', 'type': 'app'},
      'constraints': [
        {
          'fixed_version' : '2024.3.31', 'fixed_display': '2024.3.31 / 2025.1.26'
        },
        {
          'min_version': '2025.0.0', 'fixed_version': '2025.1.26', 'fixed_display': '2025.1.26'
        }
      ] 
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
