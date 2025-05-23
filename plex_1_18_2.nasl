#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137327);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id("CVE-2020-5740");

  script_name(english:"Plex Media Server < 1.18.2 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A client-server media player running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Plex Media Server installed on the remote Windows host is
prior to 1.18.2. It is, therefore, affected by a local privilege escalation vulnerability. The vulnerability exists
in the Plex Update Service due to exposed functionality over an ALPC port. An unauthenticated, local attacker can
exploit this, via the ALPC port, to execute arbitrary commands with SYSTEM privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2020-25");
  script_set_attribute(attribute:"see_also", value:"https://forums.plex.tv/t/security-regarding-cve-2020-5740/579634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Plex Media Server version 1.18.2 or later. Versions 1.19.1.2701, 1.19.2.2702, or later, are recommended by
Plex, as those versions include additional hardening to protect against future vulnerabilities.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5740");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plex:plex_media_server");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("plex_detect.nbin", "os_fingerprint.nasl", "plex_win_installed.nbin");
  script_require_keys("installed_sw/Plex Media Server", "Host/OS");

  exit(0);
}

include('http.inc');
include('vcf.inc');

# This vulnerability only affects Windows hosts
os = get_kb_item_or_exit('Host/OS');
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows');

app_info = vcf::combined_get_app_info(app:'Plex Media Server');

constraints = [
  { 'fixed_version' : '1.18.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
