#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186643);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2023-50164");
  script_xref(name:"IAVA", value:"2023-A-0675-S");

  script_name(english:"Apache Struts 2.5.0 < 2.5.33 / 6.0.0 < 6.3.0.2 Remote Code Execution (S2-066)");

  script_set_attribute(attribute:"synopsis", value:
"Apache Struts installed on the remote host is affected by Remote Code Execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote host is prior to 2.5.33 or 6.3.0.2. It is, therefore, affected by a
vulnerability as referenced in the S2-066 advisory.

  - An attacker can manipulate file upload params to enable paths traversal and under some circumstances this
    can lead to uploading a malicious file which can be used to perform Remote Code Execution.
    (CVE-2023-50164)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.33 or 6.3.0.2 or later. Alternatively, apply the workaround as referenced in in the
vendor's security bulletin");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '2.0.0', 'max_version' : '2.3.37', 'fixed_version' : '2.5.33' },
  { 'min_version' : '2.5.0', 'max_version' : '2.5.32', 'fixed_version' : '2.5.33' },
  { 'min_version' : '6.0.0', 'max_version' : '6.3.0', 'fixed_version'  : '6.3.0.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
