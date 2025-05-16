#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196901);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2024-24788");
  script_xref(name:"IAVB", value:"2024-B-0052-S");

  script_name(english:"Golang 1.22.x < 1.22.3 DoS");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is 1.22.x prior to 1.22.2. It is, therefore, affected by a denial of 
service (DoS) vulnerability. A malformed DNS message in response to a query can cause the Lookup functions to get stuck
in an infinite loop.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://pkg.go.dev/vuln/GO-2024-2824");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-announce/c/wkkO4P9stm0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.22.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin", "golang_macos_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:win_local);

var constraints = [
  { 'min_version' : '1.22.0', 'fixed_version' : '1.22.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);