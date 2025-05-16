#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189995);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id(
    "CVE-2023-39276",
    "CVE-2023-39277",
    "CVE-2023-39278",
    "CVE-2023-39279",
    "CVE-2023-39280",
    "CVE-2023-41711",
    "CVE-2023-41712",
    "CVE-2023-41713",
    "CVE-2023-41715"
  );

  script_name(english:"SonicWall SonicOS Multiple Vulnerabilities (SNWLID-2023-0012)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities including Stack-Based Buffer Overflow, Use of 
Hard-coded Password, and Improper Privilege Management.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by multiple vulnerabilities with impact to SonicOS Management Web Interface and SSLVPN Portal, but not SonicWall SSLVPN 
SMA100 and SMA1000 series products. These vulnerabilities include:

  - Post-authentication Stack-Based Buffer Overflow Vulnerability that leads to a firewall crash in:
    - getBookmarkList.json (CVE-2023-39276)
    - sonicflow.csv, appflowsessions.csv (CVE-2023-39277)
    - main.cgi (CVE-2023-39278)
    - getPacketReplayData.json (CVE-2023-39279)
    - gssoStats-s.xml, ssoStats-s.wri (CVE-2023-39280)
    - sonicwall.exp, prefs.exp (CVE-2023-41711)
    - SSL VPN plainprefs.exp (CVE-2023-41712)

  - SonicOS Use of Hard-coded Password vulnerability in the dynHandleBuyToolbar demo function. (CVE-2023-41713)

  - SonicOS post-authentication Improper Privilege Management vulnerability in the SonicOS SSL VPN Tunnel allows
    users to elevate their privileges inside the tunnel. (CVE-2023-41715)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2023-0012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29741d06");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

var os = get_kb_item_or_exit('Host/OS');
if (os !~ "^SonicOS" ) audit(AUDIT_OS_NOT, 'SonicWall SonicOS');

var match = pregmatch(pattern:"^SonicOS(?: Enhanced)? ([0-9.]+)(-[^ ]*)? on a SonicWALL (.*)$", string:os);
if (isnull(match)) exit(1, 'Failed to identify the version of SonicOS.');
var version = match[1];
var ext = match[2];
var model = match[3];

var full_ver = version + ext;

if (!empty_or_null(ext))
  ext = ext - '-';
else
  ext = '';

var fix = NULL;

# GEN6: 
# - SOHOW, TZ 300, TZ 300W, TZ 400, TZ 400W, TZ 500, TZ 500W, TZ 600, NSA 2600, NSA 2650,
# - NSA 3600, NSA 3650, NSA 4600, NSA 4650, NSA 5600, NSA 5650, NSA 6600, NSA 6650, SM 9200, SM 9250,
# - SM 9400, SM 9450, SM 9600, SM 9650, TZ 300P, TZ 600P, SOHO 250, SOHO 250W, TZ 350, TZ 350W
# fixed 6.5.4.13-105n and higher versions
if (version =~ "^6\.")
{  
  if (model =~ "TZ[3-6]00|TZ350|NSA [2-6]6[05]0|SuperMassive 9[246][05]0|SOHO" && 
      (ver_compare(ver:version,fix:'6.5.4.13',strict:FALSE) < 0 || 
      (version =~ "^6\.5\.4\.13" && ext =~ "^([0-9]?[0-9]|10[0-4])[a-z]?$"))) 
    fix = '6.5.4.13-105n and later'; 
  # cannot check for NSv Virtual platform SonicOSv
}
# GEN7
# - TZ270, TZ270W, TZ370, TZ370W, TZ470, TZ470W, TZ570, TZ570W, TZ570P, TZ670, NSA2700, NSA3700
# fixed: 7.0.1-5145 (R5175) and higher
# - NSA4700, NSA5700, NSA6700, NSSP10700, NSSP11700, NSSP13700
# fixed: 7.0.1-5145 (R5176) and higher versions
# - NSSP15700
# fixed: 7.0.1-5145 (R1468) and higher version
else if (version =~ "^7\.")
{
  if (model =~ "TZ[2-6]70|NSA [2-3]700" && (version =~ "7\.0\.0" ||
       (version =~ "7\.0\.1" && ext =~ "^([0-9]?[0-9]?[0-9]|[1-4][0-9][0-9][0-9]|50[0-9][0-9]|51[0-3][0-9]||514[0-4])[a-z]?$")))
    fix = '7.0.1-5145 (R5175) and later';
  else if (model =~ "NSSP 1[13]700|NSA [4-6]700" && (version =~ "7\.0\.0" ||
       (version =~ "7\.0\.1" && ext =~ "^([0-9]?[0-9]?[0-9]|[1-4][0-9][0-9][0-9]|50[0-9][0-9]|51[0-3][0-9]||514[0-4])[a-z]?$")))
    fix = '7.0.1-5145 (R5176) and later';
  else if (model =~ "NSSP 15700" && (version =~ "7\.0\.0" ||
       (version =~ "7\.0\.1" && ext =~ "^([0-9]?[0-9]?[0-9]|[1-4][0-9][0-9][0-9]|50[0-9][0-9]|51[0-3][0-9]||514[0-4])[a-z]?$")))
    fix = '7.0.1-5145 (R1468) and later';
  # cannot check for NSv Virtual platform
}

if (isnull(fix))
  audit(AUDIT_DEVICE_NOT_VULN, 'SonicWALL ' + model, 'SonicOS ' + full_ver);
else
{
  var port = 0;
  var report =
    '\n  Installed SonicOS version : ' + full_ver +
    '\n  Fixed SonicOS version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}

