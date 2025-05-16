#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233416);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-22230");
  script_xref(name:"VMSA", value:"2025-0005");
  script_xref(name:"IAVA", value:"2025-A-0199");

  script_name(english:"VMware Tools 11.x / 12.x < 12.5.1 Authentication Bypass (VMSA-2025-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The virtualization tool suite is installed on the remote Windows host is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is 11.x or 12.x prior to 12.5.1. It is,
therefore, affected by an authentication bypass vulnerability:

  - VMware Tools for Windows contains an authentication bypass vulnerability due to improper access control. A
    malicious actor with non-administrative privileges on a guest VM may gain ability to perform certain high
    privilege operations within that VM. (CVE-2025-22230)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25518
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3be7ddf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 12.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22230");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'requires': [
    {'scope': 'target', 'match': {'os': 'windows'}}
  ],
  'checks': [
    {
      'product': {'name': 'VMware Tools', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints' : [
        {'min_version':'11.0', 'fixed_version':'12.4.6', 'fixed_display': '12.5.1'},
        {'min_version':'12.5', 'fixed_version': '12.5.1'}
      ]
    }
  ]
};

var vdf_result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:vdf_result);