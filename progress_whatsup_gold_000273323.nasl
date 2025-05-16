#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214320);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id("CVE-2024-12105", "CVE-2024-12106", "CVE-2024-12108");
  script_xref(name:"IAVA", value:"2025-A-0014-S");

  script_name(english:"Progress WhatsUp Gold < 24.0.2 Multiple Vulnerabilities (000273323)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Progress WhatsUp Gold installed on the remote host is prior to 24.0.2. It is, therefore, affected by 
multiple vulnerabilities:

  - In WhatsUp Gold versions released before 2024.0.2, an attacker can gain access to the WhatsUp Gold server via the
    public API. (CVE-2024-12108)

  - In WhatsUp Gold versions released before 2024.0.2, an unauthenticated attacker can configure LDAP settings.
    (CVE-2024-12106)

  - In WhatsUp Gold versions released before 2024.0.2, an authenticated user can use a specially crafted HTTP request
    that can lead to information disclosure. (CVE-2024-12105)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/WhatsUp-Gold-Security-Bulletin-December-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd9b01dd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress WhatsUp Gold 24.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12108");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:whatsup_gold");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:whatsup_gold");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ipswitch_whatsup_gold_installed.nasl", "ipswitch_whatsup_gold_detect.nbin");
  script_require_keys("installed_sw/Ipswitch WhatsUp Gold");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Ipswitch WhatsUp Gold');

var constraints = [
  { 'fixed_version' : '24.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
