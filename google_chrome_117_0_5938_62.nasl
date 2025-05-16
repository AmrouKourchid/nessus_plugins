#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181291);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id(
    "CVE-2023-4863",
    "CVE-2023-4900",
    "CVE-2023-4901",
    "CVE-2023-4902",
    "CVE-2023-4903",
    "CVE-2023-4904",
    "CVE-2023-4905",
    "CVE-2023-4906",
    "CVE-2023-4907",
    "CVE-2023-4908",
    "CVE-2023-4909"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");
  script_xref(name:"IAVA", value:"2023-A-0466-S");

  script_name(english:"Google Chrome < 117.0.5938.62 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 117.0.5938.62. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_09_stable-channel-update-for-desktop_12 advisory.

  - Heap buffer overflow in WebP allowed a remote attacker to perform an out of
    bounds memory write via a crafted HTML page. (Chromium security severity:
    Critical) (CVE-2023-4863)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_12.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66ec415e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1479274");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1430867");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1459281");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1454515");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1446709");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1453501");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1441228");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1449874");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1462104");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1451543");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1463293");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 117.0.5938.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_chrome_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('SMB/Google_Chrome/Installed');
var installs = get_kb_list('SMB/Google_Chrome/*');

var product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< product_name)
  audit(AUDIT_OS_SP_NOT_VULN);

google_chrome_check_version(installs:installs, fix:'117.0.5938.62', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
