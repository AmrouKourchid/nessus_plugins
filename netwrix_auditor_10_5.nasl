#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178718);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/22");

  script_cve_id("CVE-2022-31199");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/08/01");

  script_name(english:"Netwrix Auditor < 10.5 Insecure Object Deserialization");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an insecure object deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Netwrix Auditor installed on the remote Windows host is prior to 10.5. It is, therefore, affected by an
insecure object deserialization vulnerability:

  - Netwrix Auditor is vulnerable to an insecure object deserialization issue that is caused by an unsecured .NET
    remoting service. An attacker can submit arbitrary objects to the application through this service to achieve
    remote code execution on Netwrix Auditor servers. (CVE-2022-31199)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bishopfox.com/blog/netwrix-auditor-advisory");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Netwrix Auditor version 10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netwrix:auditor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netwrix_auditor_win_installed.nbin");
  script_require_keys("installed_sw/Netwrix Auditor", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Netwrix Auditor', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '10.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
