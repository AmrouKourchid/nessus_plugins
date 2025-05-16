#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234134);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2025-32054");
  script_xref(name:"IAVA", value:"2025-A-0226");

  script_name(english:"IntelliJ IDEA < 2024.2.4 / 2024.3 (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of IntelliJ IDEA installed on the remote host is prior to 2024.2.4, 2024.3. It is, therefore, affected by a
vulnerability as referenced in the advisory.

  - In JetBrains IntelliJ IDEA before 2024.3, 2024.2.4 source code could be logged in the idea.log file
    (CVE-2025-32054)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.jetbrains.com/privacy-security/issues-fixed/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IntelliJ IDEA version 2024.2.4, 2024.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32054");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:intellij_idea");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("intellij_idea_macos_installed.nbin");
  script_require_keys("installed_sw/IntelliJ IDEA", "Host/MacOSX/Version");

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
      'product': {'name': 'IntelliJ IDEA', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'fixed_version' : '2024.2.4', 'fixed_display' : '2024.2.4, 2024.3' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_NOTE);
vdf::handle_check_and_report_errors(vdf_result:result);
