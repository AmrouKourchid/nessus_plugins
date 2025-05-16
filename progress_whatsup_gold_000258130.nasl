#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205145);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_cve_id(
    "CVE-2024-4883",
    "CVE-2024-4884",
    "CVE-2024-4885",
    "CVE-2024-5008",
    "CVE-2024-5009",
    "CVE-2024-5010",
    "CVE-2024-5011",
    "CVE-2024-5012",
    "CVE-2024-5013",
    "CVE-2024-5014",
    "CVE-2024-5015",
    "CVE-2024-5016",
    "CVE-2024-5017",
    "CVE-2024-5018",
    "CVE-2024-5019"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/24");

  script_name(english:"Progress WhatsUp Gold < 23.1.3 Multiple Vulnerabilities (000258130)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Progress WhatsUp Gold installed on the remote host is prior to 23.1.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the 000258130 advisory, including:

  - In WhatsUp Gold versions released before 2023.1.3, a Remote Code Execution issue exists in Progress WhatsUp Gold.
    This vulnerability allows an unauthenticated attacker to achieve the RCE as a service account through NmApi.exe.
    (CVE-2024-4883)

  - In WhatsUp Gold versions released before 2023.1.3, an unauthenticated Remote Code Execution vulnerability in
    Progress WhatsUpGold. The Apm.UI.Areas.APM.Controllers.CommunityController allows execution of commands with
    iisapppool\nmconsole privileges. (CVE-2024-4884)

  - In WhatsUp Gold versions released before 2023.1.3, an unauthenticated Remote Code Execution vulnerability in
    Progress WhatsUpGold. The WhatsUp.ExportUtilities.Export.GetFileWithoutZip allows execution of commands with
    iisapppool\nmconsole privileges.  (CVE-2024-4885)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-June-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29c3f424");
  script_set_attribute(attribute:"solution", value:
"Update to Progress WhatsUp Gold version 23.1.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4885");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:whatsup_gold");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_whatsup_gold_installed.nasl", "ipswitch_whatsup_gold_detect.nbin");
  script_require_keys("installed_sw/Ipswitch WhatsUp Gold");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Ipswitch WhatsUp Gold');

var constraints = [
  { 'fixed_version' : '23.1.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
