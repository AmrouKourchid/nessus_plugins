#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178720);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-38404");
  script_xref(name:"IAVB", value:"2023-B-0054-S");

  script_name(english:"Veritas InfoScale Operations Manager prior to  8.0.0.410 Insecure File Upload (VTS23-009)");

  script_set_attribute(attribute:"synopsis", value:
"A storage management application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Veritas InfoScale Operations Manager application installed on the remote host is prior to 8.0.0.410. It is,
therefore, affected by an insecure file upload vulnerability. 

  - The VIOM XPRTLD web application allows an authenticated attacker to upload all types of files to the server. An
    authenticated attacker can then execute the malicious file to perform command execution on the remote server.
    (CVE-2023-38404)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS23-009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas InfoScale Operations Manager version 8.0.0.410 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:infoscale_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_infoscale_operations_manager_nix_installed.nbin", "veritas_infoscale_operations_manager_win_installed.nbin");
  script_require_keys("installed_sw/Veritas InfoScale Operations Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Veritas InfoScale Operations Manager');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '7.4.2.810' },
  { 'min_version' : '8.0', 'fixed_version' : '8.0.0.410' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
