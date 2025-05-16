#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198215);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/06");

  script_cve_id("CVE-2024-4561", "CVE-2024-4562");
  script_xref(name:"IAVA", value:"2024-A-0318-S");

  script_name(english:"Progress WhatsUp Gold < 23.1.2 Multiple Vulnerabilities (000255428)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Progress WhatsUp Gold installed on the remote host is prior to 23.1.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the 000255428 advisory.

  - In WhatsUp Gold versions released before 2023.1.2, a blind SSRF vulnerability exists in Whatsup Gold's
    FaviconController that allows an attacker to send arbitrary HTTP requests on behalf of the vulnerable
    server. (CVE-2024-4561)

  - In WhatsUp Gold versions released before 2023.1.2, an SSRF vulnerability exists in Whatsup Gold's Issue
    exists in the HTTP Monitoring functionality. Due to the lack of proper authorization, any authenticated
    user can access the HTTP monitoring functionality, what leads to the Server Side Request Forgery.
    (CVE-2024-4562)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://community.progress.com/s/article/Announcing-WhatsUp-Gold-v2023-1-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?204c2e7f");
  script_set_attribute(attribute:"solution", value:
"Upgrade Progress Ipswitch WhatsUp Gold based upon the guidance specified in Article 000255428.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/31");

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
  { 'fixed_version' : '23.1.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
