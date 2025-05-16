#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180273);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2023-40217");
  script_xref(name:"IAVA", value:"2023-A-0442-S");

  script_name(english:"Python TLS Handshake Bypass (CVE-2023-40217)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Python installed on the remote Windows host is potentially affected by a vulnerability that primarily
affects servers (such as HTTP servers) that use TLS client authentication. If a TLS server-side socket is created,
receives data into the socket buffer, and then is closed quickly, there is a brief window where the SSLSocket instance
will detect the socket as 'not connected' and won't initiate a handshake, but buffered data will still be readable from
the socket buffer. This data will not be authenticated if the server-side TLS peer is expecting client certificate
authentication, and is indistinguishable from valid TLS stream data. Data is limited in size to the amount that will fit
in the buffer. (The TLS connection cannot directly be used for data exfiltration because the vulnerable code path
  requires that the connection be closed on initialization of the SSLSocket.)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://mail.python.org/archives/list/security-announce@python.org/thread/PEPLII27KYHLF4AK3ZQGKYNCRERG4YXY/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42fdcc28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Python 3.11.5, 3.10.13, 3.9.18, 3.8.18 or later, apply a patch, or see workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

# We cannot test for patch/workaround
if (report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, 'Python', app_info.display_version);

# app_info.version holds file version, like 3.7.11150.1013, which has no public translation to the version we want
# app_info.display_version holds correct version, so swap these
app_info.version = app_info.display_version;
app_info.parsed_version = vcf::parse_version(app_info.version);


var constraints = [
  {'min_version':'0.0', 'max_version': '3.7.17', 'fixed_display':'See vendor advisory' },
  {'min_version':'3.8',   'fixed_version' : '3.8.18'},
  {'min_version':'3.9',   'fixed_version' : '3.9.18'},
  {'min_version':'3.10',   'fixed_version' : '3.10.13'},
  {'min_version':'3.11',   'fixed_version' : '3.11.5'},
  {'min_version':'3.12.0rc1',   'fixed_version' : '3.12.0rc2'} # no alpha releases seen, flagging only rc1 should be fine
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
