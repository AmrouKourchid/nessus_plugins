#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233657);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id("CVE-2024-47072");

  script_name(english:"Atlassian Jira Service Management Data Center and Server 5.7 < 5.12.19 / 5.13.x < 10.3.4 / 10.4.x < 10.5.0 (JSDSERVER-16086)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host
is affected by a vulnerability as referenced in the JSDSERVER-16086 advisory.

  - XStream is a simple library to serialize objects to XML and back again. This vulnerability may allow a
    remote attacker to terminate the application with a stack overflow error resulting in a denial of service
    only by manipulating the processed input stream when XStream is configured to use the BinaryStreamDriver.
    XStream 1.4.21 has been patched to detect the manipulation in the binary input stream causing the the
    stack overflow and raises an InputManipulationException instead. Users are advised to upgrade. Users
    unable to upgrade may catch the StackOverflowError in the client code calling XStream if XStream is
    configured to use the BinaryStreamDriver. (CVE-2024-47072)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-16086");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.12.19, 10.3.4, 10.5.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product':{'name': 'JIRA Service Desk Application', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        { 'min_version':'5.7', 'fixed_version':'5.12.19' },
        { 'min_version':'5.13', 'fixed_version':'10.3.4' },
        { 'min_version':'10.4.0', 'fixed_version':'10.5.0' }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
