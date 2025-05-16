#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193339);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2023-47359", "CVE-2023-47360");
  script_xref(name:"IAVB", value:"2024-B-0004-S");

  script_name(english:"VLC < 3.0.20 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior to 3.0.20. It is, therefore, affected by multiple
vulnerabilities:

  - Videolan VLC prior to version 3.0.20 contains an incorrect offset read that leads to a Heap-Based Buffer
    Overflow in function GetPacket() and results in a memory corruption. (CVE-2023-47359)

  - Videolan VLC prior to version 3.0.20 contains an Integer underflow that leads to an incorrect packet
    length. (CVE-2023-47360)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sb-vlc3020.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.20 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47359");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl", "macosx_vlc_installed.nbin");
  script_require_ports("installed_sw/VLC media player", "installed_sw/VLC");

  exit(0);
}

include('vcf.inc');

var app;
var os = get_kb_item('Host/MacOSX/Version');
var win_local = FALSE;

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

if (!isnull(os))
    app = 'VLC';
else
    app = 'VLC media player';

var app_info = vcf::get_app_info(app:app, win_local:win_local);

var constraints = [{'fixed_version':'3.0.20'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
