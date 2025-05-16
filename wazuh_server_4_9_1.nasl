#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235712);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id("CVE-2025-24016");
  script_xref(name:"IAVA", value:"2025-A-0297");

  script_name(english:"Wazuh Server 4.4.0 < 4.9.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a threat prevention, detection, and response platform that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Wazuh Server on the remote host is at least 4.4.0 and prior to 4.9.1. It is, therefore, affected by a
remote code execution vulnerability:

  - Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for
    remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and
    deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages
    to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception
    (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody
    with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations,
    even by a compromised agent. Version 4.9.1 contains a fix. (CVE-2025-24016)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/wazuh/wazuh/security/advisories/GHSA-hcrc-79hj-m3qh");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wazuh Server version 4.9.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24016");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wazuh:wazuh");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wazuh_server_nix_installed.nbin");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Wazuh-Manager', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version': '4.4.0', 'fixed_version': '4.9.1'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
