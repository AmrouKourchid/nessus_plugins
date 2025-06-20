#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(147227);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2021-24089",
    "CVE-2021-26902",
    "CVE-2021-27047",
    "CVE-2021-27048",
    "CVE-2021-27049",
    "CVE-2021-27050",
    "CVE-2021-27051",
    "CVE-2021-27061",
    "CVE-2021-27062"
  );

  script_name(english:"Microsoft Windows Codecs Library Multiple Vulnerabilities (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows 'HEVC Video Extensions' or 'HEVC from Device Manufacturer' app
installed on the remote host is affected by multiple remote code execution
vulnerabilities:

  - A remote code execution vulnerability exists in the Microsoft Windows
  Codecs Library HEVC Extension. An attacker who successfully exploited the
  vulnerability could execute arbitrary code.  Exploitation of the
  vulnerability requires that a program process a specially crafted file.
  (CVE-2021-24089, CVE-2021-27062, CVE-2021-27061, CVE-2021-27051, CVE-2021-27050, 
  CVE-2021-27049, CVE-2021-27048, CVE-2021-27047, CVE-2021-26902)");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24089
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?382e07dc");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27062
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8434e679");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27061
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa84ab3a");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27051
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bfedbc2");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27050
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91b85c29");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0241194");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27048
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c90fef8f");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27047
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4804db51");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26902
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daae3531");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 1.0.40203.0, 1.0.40204.0, or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27062");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:high_efficiency_video_coding");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "WMI/Windows App Store/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

# Thanks to MS for two nearly identical package identity names:
#  Microsoft.HEVCVideoExtension  - HEVC Video Extensions from Device Manufacturer
#  Microsoft.HEVCVideoExtensions - HEVC Video Extensions
var apps = ['Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions'];

var app_info = vcf::microsoft_appstore::get_app_info(app_list:apps);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '1.0.40203.0', 'fixed_display' : '1.0.40203.0 / 1.0.40204.0'}
];

vcf::microsoft_appstore::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
