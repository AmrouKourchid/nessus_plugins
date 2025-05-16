#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213040);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id("CVE-2024-53677");
  script_xref(name:"IAVA", value:"2024-A-0821");

  script_name(english:"Apache Struts 2.0.0 <=> 2.3.37(EOL) / 2.5.0 <=> 2.5.33 / 6.0.0 <=> 6.3.0.2 Remote Code Execution (S2-067)");

  script_set_attribute(attribute:"synopsis", value:
"Apache Struts installed on the remote host is affected by Remote Code Execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the S2-067 advisory.

  - File upload logic is flawed vulnerability in Apache Struts. This issue affects Apache Struts: from 2.0.0
    before 6.4.0. Users are recommended to upgrade to version 6.4.0 migrate to the new file upload mechanism
    https://struts.apache.org/core-developers/file-upload . You can find more details in
    https://cwiki.apache.org/confluence/display/WW/S2-067 (CVE-2024-53677)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-067");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version  or later. Alternatively, apply the workaround as referenced in in the vendor's
security bulletin");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/S:N/AU:Y/R:A/V:C/RE:L/U:Red");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53677");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
var win_local = ('windows' >< tolower(os));

var app_info = vcf::get_app_info(app:'Apache Struts', win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.3.37', 'fixed_display' : 'Upgrade to a version greater than 2.3.37(EOL)' },
  { 'min_version' : '2.5.0', 'max_version' : '2.5.33', 'fixed_display' : 'Upgrade to a version greater than 2.5.33' },
  { 'min_version' : '6.0.0', 'max_version' : '6.3.0.2', 'fixed_display' : 'Upgrade to a version greater than 6.3.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
