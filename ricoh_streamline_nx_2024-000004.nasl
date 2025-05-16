#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200808);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/24");

  script_cve_id("CVE-2024-36252");
  script_xref(name:"IAVB", value:"2024-B-0081");

  script_name(english:"Streamline NX Client < 3.4.3.2 / 3.5.x < 3.5.1.202 / 3.6.x < 3.6.2.2 RCE (2024-000004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Streamline NX Client installed on the remote host is prior to 3.231.0, 3.4.3.2, 3.5.1.202 or 3.6.2.2.
It is, therefore, affected by a vulnerability as referenced in the 2024-000004 advisory.

  - Improper restriction of communication channel to intended endpoints issue exists in Ricoh Streamline NX PC
    Client ver.3.6.x and earlier. If this vulnerability is exploited, arbitrary code may be executed on the PC
    where the product is installed.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2024-000004
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?946f6d82");
  # https://www.ricoh.com/products/security/vulnerabilities/adv?id=ricoh-prod000077-2024-000004
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebc8b722");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Streamline NX Client version 3.231.0 / 3.4.3.2 / 3.5.1.202 / 3.6.2.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-36252");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ricoh:streamline_nx_client_tool");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ricoh_streamline_nx_win_installed.nbin");
  script_require_keys("installed_sw/Streamline NX Client");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Streamline NX Client');

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '3.4.3.2' },
  { 'min_version' : '3.5', 'fixed_version' : '3.5.1.202' },
  { 'min_version' : '3.6', 'fixed_version' : '3.6.2.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
