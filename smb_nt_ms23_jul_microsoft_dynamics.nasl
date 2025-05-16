#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178184);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id(
    "CVE-2023-33171",
    "CVE-2023-35335",
    "CVE-2023-35389",
    "CVE-2023-36416"
  );
  script_xref(name:"MSKB", value:"5026500");
  script_xref(name:"MSKB", value:"5026501");
  script_xref(name:"MSFT", value:"MS23-5026500");
  script_xref(name:"MSFT", value:"MS23-5026501");
  script_xref(name:"IAVA", value:"2023-A-0339-S");
  script_xref(name:"IAVA", value:"2023-A-0407-S");
  script_xref(name:"IAVA", value:"2023-A-0544-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote attacker can craft a specially-constructed URL which, when accessed by an authorised user,
    allows the attacker to retrieve cookies, present the user with a dialog box to enter credentials,
    or redirect that user to a malicious site. (CVE-2023-33171, CVE-2023-35335)

  - An authenticated, remote attacker can force a bad response to be cached into a regular URL by having
    multiple occurrences of the same variable in a query string. The impact is dependent on the business
    logic of the use application. (CVE-2023-35389)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5026500");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5026501");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB 5026500
  -KB 5026501");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35335");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.47.08', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.47' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.18.22', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.18' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags: {'xss': TRUE}
);
