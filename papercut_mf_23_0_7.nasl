#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193336);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2024-1221",
    "CVE-2024-1222",
    "CVE-2024-1223",
    "CVE-2024-1654",
    "CVE-2024-1882",
    "CVE-2024-1883",
    "CVE-2024-1884"
  );

  script_name(english:"PaperCut MF < 20.1.10 / 21.x < 21.2.14 / 22.x < 22.1.5 / 23.x < 23.0.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"PaperCut MI installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PaperCut MF installed on the remote Windows host is affected by multiple vulnerabilities, as follows:

    - This allows attackers to use a maliciously formed API request to gain access to an API authorization level with
      elevated privileges. This applies to a small subset of PaperCut NG/MF API calls. (CVE-2024-1222)

    - This vulnerability potentially allows unauthorized write operations which may lead to remote code execution.
      An attacker must already have authenticated admin access and knowledge of both an internal system identifier
      and details of another valid user to exploit this. (CVE-2024-1654)

    - This vulnerability allows an already authenticated admin user to create a malicious payload that could be
      leveraged for remote code execution on the server hosting the PaperCut NG/MF application server. (CVE-2024-1882)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.papercut.com/kb/Main/Security-Bulletin-March-2024");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PaperCut MF version 20.1.10, 21.2.14, 22.1.5, 23.0.7, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:papercut:papercut_mf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("papercut_mf_win_installed.nbin");
  script_require_keys("installed_sw/PaperCut MF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'PaperCut MF', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '20.1.10' },
  { 'min_version' : '21.0', 'fixed_version' : '21.2.14' },
  { 'min_version' : '22.0', 'fixed_version' : '22.1.5' },
  { 'min_version' : '23.0', 'fixed_version' : '23.0.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
