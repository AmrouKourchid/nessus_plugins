#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234350);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2025-2945", "CVE-2025-2946");
  script_xref(name:"IAVB", value:"2025-B-0049");

  script_name(english:"pgAdmin < 9.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The pgAdmin instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of pgAdmin installed on the remote host is prior to 9.2. It is, therefore, affected by the
following vulnerabilities:

  - Remote Code Execution security vulnerability in pgAdmin 4 (Query Tool and Cloud Deployment modules). The
    vulnerability is associated with the 2 POST endpoints; /sqleditor/query_tool/download, where the
    query_commited parameter and /cloud/deploy endpoint, where the high_availability parameter is unsafely
    passed to the Python eval() function, allowing arbitrary code execution. (CVE-2025-2945)

  - pgAdmin <= 9.1 is affected by a security vulnerability with Cross-Site Scripting(XSS). If attackers execute
    any arbitrary HTML/JavaScript in a user's browser through query result rendering, then HTML/JavaScript
    runs on the browser. (CVE-2025-2946)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/pgadmin-org/pgadmin4/issues/8603");
  script_set_attribute(attribute:"see_also", value:"https://github.com/pgadmin-org/pgadmin4/issues/8602");
  script_set_attribute(attribute:"solution", value:
"Upgrade pgAdmin to a version later than 9.2.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2945");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:pgadmin_4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_pgadmin4_macos_installed.nbin", "postgresql_pgadmin4_win_installed.nbin");
  script_require_ports("installed_sw/PostgreSQL pgAdmin4");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'PostgreSQL pgAdmin4', 'type': 'app'},
      'requires': [ {'scope': 'target', 'match_one': {'os': ['windows', 'macos'] } } ],
      'check_algorithm': 'default',
      'constraints': [
        {
          'fixed_version': '9.2'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
