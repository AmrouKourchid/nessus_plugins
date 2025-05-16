#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209140);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/17");

  script_cve_id(
    "CVE-2024-3037",
    "CVE-2024-4712",
    "CVE-2024-8404",
    "CVE-2024-8405"
  );

  script_name(english:"PaperCut NG < 23.0.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"PaperCut NG installed on remote Windows host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of PaperCut NG installed on the remote Windows host is affected by multiple vulnerabilities, as follows:

    - An arbitrary file deletion vulnerability exists in PaperCut NG/MF, specifically affecting Windows servers with
      Web Print enabled. To exploit this vulnerability, an attacker must first obtain local login access to the
      Windows Server hosting PaperCut NG/MF and be capable of executing low-privilege code directly on the server. The
      attacker can leverage this attack by creating a symbolic link, and use this service to delete the file the link
      is pointing to. (CVE-2024-3037)

    - This vulnerability could potentially allow the creation of files in specific locations used by the Web Print
      service. This vulnerability only applies to PaperCut NG/MF Windows servers with the PaperCut Web Print Server
      service enabled and uses the image-handler process, which can incorrectly create files that don’t exist when a
      maliciously formed payload is provided. (CVE-2024-4712)

    - CVE-2024-8404 and CVE-2024-8405 have been split to allow the researchers (Trend Micro ZDI) to attribute two 
      instances of the same vulnerability type to different reporters. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.papercut.com/kb/Main/Security-Bulletin-May-2024");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PaperCut NG version 23.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:papercut:papercut_ng");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("papercut_ng_win_installed.nbin");
  script_require_keys("installed_sw/PaperCut NG", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'PaperCut NG', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '23.0.9' },
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
