#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234498);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id("CVE-2025-2572");
  script_xref(name:"TRA", value:"TRA-2025-13");
  script_xref(name:"IAVA", value:"2025-A-0276");

  script_name(english:"Progress WhatsUp Gold < 24.0.3 Database Manipulation (CVE-2025-2572)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Progress WhatsUp Gold installed on the remote host is prior to 24.0.3. It is, therefore, affected by a
database manipulation vulnerability:

  - In WhatsUp Gold versions released before 2024.0.3, a database manipulation vulnerability allows an unauthenticated
    attacker to modify the contents of WhatsUp.dbo.WrlsMacAddressGroup. (CVE-2025-2572)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.progress.com/bundle/whatsupgold-release-notes-24-0/page/WhatsUp-Gold-2024.0-Release-Notes.html#ariaid-title30
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e0d08e7");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2025-13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress WhatsUp Gold 24.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2572");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

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

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Ipswitch WhatsUp Gold', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {'fixed_version': '24.0.3'}
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
