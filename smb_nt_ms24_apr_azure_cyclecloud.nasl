#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(193144);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/12");

  script_cve_id("CVE-2024-29993");
  script_xref(name:"IAVA", value:"2024-A-0224");

  script_name(english:"Security Updates for Azure CycleCloud (April 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure CycleCloud product is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Azure CycleCloud product is missing security updates. 
It is, therefore, affected by an elevation of privilege vulnerability. The attacker who successfully exploited 
this vulnerability could elevate privileges to the SuperUser role in the affected Azure CycleCloud instance.
To exploit this vulnerability an attacker must have an account with the User role assigned.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29993
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f8a6b69");
  # https://learn.microsoft.com/en-us/azure/cyclecloud/release-notes/8-6-1?view=cyclecloud-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d326a2f6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released CycleCloud version 8.6.1 to address this issue");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29993");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_cyclecloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("azure_cyclecloud_web_detect.nbin", "microsoft_azure_cyclecloud_web_detect.nbin");
  script_require_keys("installed_sw/Microsoft Azure CycleCloud");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Microsoft Azure CycleCloud', webapp:TRUE, port:port);

var constraints = [  
  {'min_version': '8.6.0', 'fixed_version': '8.6.1'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
