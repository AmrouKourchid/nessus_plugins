#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232871);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2020-36843", "CVE-2025-30196", "CVE-2025-30197");
  script_xref(name:"JENKINS", value:"2025-03-19");

  script_name(english:"Jenkins plugins Multiple Vulnerabilities (2025-03-19)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to their self-reported version numbers, the version of Jenkins plugins running on the remote web server are
affected by multiple vulnerabilities:

  - The implementation of EdDSA in EdDSA-Java (aka ed25519-java) through 0.3.0 exhibits signature malleability
    and does not satisfy the SUF-CMA (Strong Existential Unforgeability under Chosen Message Attacks)
    property. This allows attackers to create new valid signatures different from previous signatures for a
    known message. (CVE-2020-36843)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jenkins.io/security/advisory/2025-03-19");
  script_set_attribute(attribute:"solution", value:
"Update Jenkins plugins to the following versions:
  - AnchorChain Plugin: See vendor advisory
  - EDDSA API Plugin to version 0.3.0.1-16.vcb_4a_98a_3531c or later
  - Zoho QEngine Plugin to version 1.0.31.v4a_b_1db_6d6a_f2 or later

See vendor advisory for more details.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30196");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-36843");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jenkins:jenkins");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_plugins_detect.nbin", "jenkins_win_installed.nbin", "jenkins_nix_installed.nbin", "macosx_jenkins_installed.nbin");
  script_require_keys("installed_sw/Jenkins");

  exit(0);
}

include('vcf_extras.inc');

var constraints = [
    {'max_version' : '1.0', 'fixed_display' : 'See vendor advisory', 'plugin' : 'AnchorChain Plugin'},
    {'max_version' : '0.3.0', 'fixed_version' : '0.3.0.1', 'fixed_display' : '0.3.0.1-16.vcb_4a_98a_3531c', 'plugin' : 'EDDSA API Plugin'},
    {'max_version' : '1.0.29', 'fixed_version' : '1.0.31', 'fixed_display' : '1.0.31.v4a_b_1db_6d6a_f2', 'plugin' : 'Zoho QEngine Plugin'}
];

var app_info = vcf::jenkins::plugin::get_app_info(plugins:constraints);

vcf::jenkins::plugin::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
