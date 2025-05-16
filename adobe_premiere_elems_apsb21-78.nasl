#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154230);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-39824",
    "CVE-2021-40700",
    "CVE-2021-40701",
    "CVE-2021-40702",
    "CVE-2021-40703"
  );
  script_xref(name:"IAVA", value:"2021-A-0422-S");

  script_name(english:"Adobe Premiere Elements Arbitrary Code Execution (APSB21-78)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Premiere Elements instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Elements installed on the remote Windows host is prior to build 19.0
(20210809.daily.2242976). It is, therefore, affected by multiple vulnerabilities as referenced in the APSB21-78
advisory.

  - Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption
    vulnerability due to insecure handling of a malicious m4a file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-40701, CVE-2021-40703)

  - Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption
    vulnerability due to insecure handling of a malicious png file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-39824)

  - Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption
    vulnerability due to insecure handling of a malicious TIFF file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-40700)

  - Adobe Premiere Elements version 2021.2235820 (and earlier) is affected by a memory corruption
    vulnerability due to insecure handling of a malicious psd file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-40702)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb21-78.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc56e46b");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premiere Elements to build 19.0 (20210809.daily.2242976) or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Premiere Elements");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:TRUE);

var build_timestamp = app_info['Build timestamp'];

if (empty_or_null(build_timestamp))
  audit(AUDIT_UNKNOWN_BUILD, app_info['app'], app_info['version']);

if (
  app_info.version =~ "^19\.0" &&
  ver_compare(ver:app_info['Build timestamp'], fix:'20210809', strict:FALSE) < 0
)
{
  app_info['display_version'] = app_info['version'] + ' ' + app_info['Build info'];
  vcf::report_results(app_info:app_info, fix:'build 19.0 (20210809.daily.2242976)', severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}
