#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206233);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2024-6670",
    "CVE-2024-6671",
    "CVE-2024-6672",
    "CVE-2024-7763"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/07");
  script_xref(name:"IAVA", value:"2024-A-0532-S");

  script_name(english:"Progress WhatsUp Gold < 24.0.0 Multiple Vulnerabilities (000263015)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Progress WhatsUp Gold installed on the remote host is prior to 24.0.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the 000263015 advisory:

  - In WhatsUp Gold versions released before 2024.0.0, if the application is configured with only a single user, a SQL
    Injection vulnerability allows an unauthenticated attacker to retrieve the users encrypted password.
    (CVE-2024-6670)

  - In WhatsUp Gold versions released before 2024.0.0, if the application is configured with only a single user, a SQL
    Injection vulnerability allows an unauthenticated attacker to retrieve the users encrypted password.
    (CVE-2024-6671)

  - In WhatsUp Gold versions released before 2024.0.0, a SQL Injection vulnerability allows an authenticated
    low-privileged attacker to achieve privilege escalation by modifying a privileged user's password. (CVE-2024-6672)

  - In WhatsUp Gold versions released before 2024.0.0, an Authentication Bypass issue exists which allows an attacker 
    to obtain encrypted user credentials. (CVE-2024-7763)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-August-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22fd5e9c");
  script_set_attribute(attribute:"solution", value:
"Update to Progress WhatsUp Gold version 24.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6671");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:whatsup_gold");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_whatsup_gold_installed.nasl", "ipswitch_whatsup_gold_detect.nbin");
  script_require_keys("installed_sw/Ipswitch WhatsUp Gold");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Ipswitch WhatsUp Gold');

var constraints = [
  { 'fixed_version' : '24.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
