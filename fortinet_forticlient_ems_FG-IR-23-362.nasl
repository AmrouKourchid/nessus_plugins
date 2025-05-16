#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2024-21753");
  script_xref(name:"IAVA", value:"2024-A-0572-S");

  script_name(english:"Fortinet FortiClient EMS < 7.2.5 (FG-IR-23-362)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient EMS installed on the remote host is prior to 7.2.5. It is, therefore,
affected by a vulnerability as referenced in the FG-IR-23-362 advisory.

  - A improper limitation of a pathname to a restricted directory ('path traversal') in Fortinet FortiClientEMS 
    versions 7.2.0 through 7.2.4, 7.0.0 through 7.0.13, 6.4.0 through 6.4.9, 6.2.0 through 6.2.9, 6.0.0 through 6.0.8, 
    1.2.1 through 1.2.5 allows attacker to perform a denial of service, read or write a limited number of files via 
    specially crafted HTTP requests 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.fortinet.com/psirt/FG-IR-23-362");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient EMS version 7.2.5 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient_enterprise_management_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_forticlient_ems_win_installed.nbin", "fortinet_forticlient_ems_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiClient EMS");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Fortinet FortiClient EMS');

var constraints = [
  { 'min_version' : '1.2.2', 'max_version' : '1.2.5', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.0.0', 'max_version' : '6.0.8', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.2.0', 'max_version' : '6.2.9', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '6.4.0', 'max_version' : '6.4.9', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '7.0.0', 'max_version' : '7.0.13', 'fixed_display' : 'See vendor advisory'},
  { 'min_version' : '7.2.0', 'fixed_version' : '7.2.5'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
