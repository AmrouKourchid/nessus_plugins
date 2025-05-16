#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152667);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2021-36070", "CVE-2021-42721", "CVE-2021-42726");
  script_xref(name:"IAVA", value:"2021-A-0382-S");

  script_name(english:"Adobe Media Encoder < 15.4.1 Multiple Arbitrary code execution (APSB21-70)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote Windows host is prior to 15.4.1. It is, therefore, affected
by multiple vulnerabilities as referenced in the APSB21-70 advisory.

  - Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious M4A file, potentially resulting in arbitrary code execution in the context of the
    current user. User interaction is required to exploit this vulnerability. (CVE-2021-42726)

  - Adobe Media Encoder version 15.1 (and earlier) is affected by an improper memory access vulnerability when
    parsing a crafted .SVG file. An attacker could leverage this vulnerability to execute code in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2021-36070)

  - Acrobat Bridge versions 11.1.1 and earlier are affected by a use-after-free vulnerability in the
    processing of Format event actions that could result in arbitrary code execution in the context of the
    current user. Exploitation of this issue requires user interaction in that a victim must open a malicious
    file. (CVE-2021-42721)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/media-encoder/apsb21-70.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Media Encoder version 15.4.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42726");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_win_installed.nbin");
  script_require_keys("installed_sw/Adobe Media Encoder", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Media Encoder', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '15.4.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
