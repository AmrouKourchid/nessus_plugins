#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211470);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2024-11168");
  script_xref(name:"IAVA", value:"2024-A-0748");

  script_name(english:"Python Improper Validation SSRF (CVE-2024-11168)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Python installed on the remote Windows host is improper validation vulnerability.  The 
urllib.parse.urlsplit() and urlparse() functions improperly validated bracketed hosts (`[]`), allowing 
hosts that weren't IPv6 or IPvFuture. This behavior was not conformant to RFC 3986 and potentially 
enabled SSRF if a URL is processed by more than one URL parser.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://mail.python.org/archives/list/security-announce@python.org/thread/XPWB6XVZ5G5KGEI63M4AWLIEUF5BPH4T/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66c7faf9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Python 3.11.4, 3.12.0b1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11168");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

# We cannot test for patch/workaround
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'0.0', 'fixed_version': '3.11.4150.1013', 'fixed_display':'3.11.4'},
  {'min_version':'3.12.101.1013', 'fixed_version' : '3.12.111.1013', 'fixed_display': '3.12.0b1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
