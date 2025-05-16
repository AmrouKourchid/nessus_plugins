#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234125);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2025-1691", "CVE-2025-1692", "CVE-2025-1693");
  script_xref(name:"IAVB", value:"2025-B-0037");

  script_name(english:"MongoDB Shell < 2.3.9 Control Character Injection (MONGOSH-2024, MONGOSH-2025, MONGOSH-2026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of MongoDB Shell installed on the remote host is prior to 2.3.9. It is, therefore, affected by
 a vulnerability as referenced in the MONGOSH-2024, MONGOSH-2025, MONGOSH-2026 advisories.

  - The MongoDB Shell may be susceptible to control character injection where an attacker with control of the 
    mongosh autocomplete feature, can use the autocompletion feature to input and run obfuscated malicious 
    text. This requires user interaction in the form of the user using ‘tab’ to autocomplete text that is a 
    prefix of the attacker’s prepared autocompletion. This issue affects mongosh versions prior to 2.3.9.  
    The vulnerability is exploitable only when mongosh is connected to a cluster that is partially or fully 
    controlled by an attacker. (CVE-2025-1691)

  - The MongoDB Shell may be susceptible to control character injection where an attacker with control of the 
    user’s clipboard could manipulate them to paste text into mongosh that evaluates arbitrary code. Control 
    characters in the pasted text can be used to obfuscate malicious code. This issue affects mongosh versions 
    prior to 2.3.9 (CVE-2025-1692)

  - The MongoDB Shell may be susceptible to control character injection where an attacker with control over the 
    database cluster contents can inject control characters into the shell output. This may result in the 
    display of falsified messages that appear to originate from mongosh or the underlying operating system, 
    potentially misleading users into executing unsafe actions. The vulnerability is exploitable only when 
    mongosh is connected to a cluster that is partially or fully controlled by an attacker. This issue affects 
    mongosh versions prior to 2.3.9 (CVE-2025-1693)

  Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
  number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/MONGOSH-2024");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/MONGOSH-2025");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/MONGOSH-2026");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB Shell version 2.3.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1691");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-1691");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mongodb:mongodb_shell");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_shell_linux_installed.nbin", "mongodb_shell_macos_installed.nbin", "mongodb_shell_win_installed.nbin");
  script_require_keys("installed_sw/MongoDB Shell");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'MongoDB Shell', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints' : [ {'fixed_version': '2.3.9'}
      ]
    }
  ]
};

var vdf_result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:vdf_result);
