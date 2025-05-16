#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233177);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-2277", "CVE-2025-2278", "CVE-2025-2280");
  script_xref(name:"IAVB", value:"2025-B-0040-S");

  script_name(english:"Devolutions Server <= 2024.3.13 Multiple Vulnerabilities (DEVO-2025-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Server instance installed on the remote host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Devolutions Server installed on the remote host is prior or equal to 2024.3.13 and is, therefore,
affected by multiple vulnerabilities:

  - Exposure of password in web-based SSH authentication component in Devolutions Server 2024.3.13 and earlier allows a
    user to unadvertently leak his SSH password due to missing password masking. (CVE-2025-2277)

  - Improper access control in temporary access requests and checkout requests endpoints in Devolutions Server
    2024.3.13 and earlier allows an authenticated user to access information about these requests via a known request
    ID. (CVE-2025-2278)

  - Improper access control in web extension restriction feature in Devolutions Server 2024.3.13 and earlier allows an
    authenticated user to bypass the browser extension restriction feature. (CVE-2025-2280)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2025-0004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Server version 2025.1.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2280");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_server_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Server", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Devolutions Server', win_local:TRUE);

var constraints = [
  { 'max_version':'2024.3.13', 'fixed_version':'2025.1.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
