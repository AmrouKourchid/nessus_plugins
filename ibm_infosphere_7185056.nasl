#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233199);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/07");

  script_cve_id("CVE-2024-51459");
  script_xref(name:"IAVB", value:"2025-B-0039-S");

  script_name(english:"IBM InfoSphere Information Server Access Control Vulnerability (7185056)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of IBM InfoSphere Information Server installed on the remote host is 11.7.0 prior to 11.7.1.136. 
It is, therefore, affected by an access control vulnerability, leading to privileged escalation, as referenced 
in the 7185056 advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/7185056");
  script_set_attribute(attribute:"solution", value:
"Upgrade IBM InfoSphere Information Server based upon the guidance specified in 7185056.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-51459");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:infosphere_information_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_infosphere_information_server.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/IBM InfoSphere Information Server");

  exit(0);
}

include('vdf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'IBM InfoSphere Information Server', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'min_version': '11.7', 'fixed_version': '11.7.1.136'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);