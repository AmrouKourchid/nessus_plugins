#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206672);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id("CVE-2024-20439", "CVE-2024-20440");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi41731");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi47950");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cslu-7gHMzWmw");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/21");

  script_name(english:"Cisco Smart Licensing Utility (CSLU) 2.x < 2.3.0 Multiple Vulnerabilities (cisco-sa-cslu-7gHMzWmw)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Smart Licensing Utility (CSLU) installed on the remote Windows host is 2.x prior to 2.3.0. It is,
therefore, affected by multiple vulnerabilities:

  - A vulnerability in Cisco Smart Licensing Utility could allow an unauthenticated, remote attacker to log in to an
    affected system by using a static administrative credential. (CVE-2024-20439)

  - A vulnerability in Cisco Smart Licensing Utility could allow an unauthenticated, remote attacker to access
    sensitive information. (CVE-2024-20440)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cslu-7gHMzWmw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bef44268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi41731");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi47950");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Smart Licensing Utility 2.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20439");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:smart_licensing_utility");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_smart_licensing_utility_win_installed.nbin");
  script_require_keys("installed_sw/Cisco Smart Licensing Utility", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Cisco Smart Licensing Utility', win_local:TRUE);

var constraints = [
  { 'min_version':'2.0.0', 'fixed_version' : '2.3.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
