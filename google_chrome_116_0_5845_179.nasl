#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180508);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id(
    "CVE-2023-4761",
    "CVE-2023-4762",
    "CVE-2023-4763",
    "CVE-2023-4764"
  );
  script_xref(name:"IAVA", value:"2023-A-0457-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/02/27");

  script_name(english:"Google Chrome < 116.0.5845.179 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote Windows host is prior to 116.0.5845.179. It is, therefore, affected
by multiple vulnerabilities as referenced in the 2023_09_stable-channel-update-for-desktop advisory.

  - Out of bounds memory access in FedCM. (CVE-2023-4761)

  - Type Confusion in V8. (CVE-2023-4762)

  - Use after free in Networks. (CVE-2023-4763)

  - Incorrect security UI in BFCache. (CVE-2023-4764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?411f6120");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1476403");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1473247");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1469928");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1447237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 116.0.5845.179 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4763");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/05");

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

google_chrome_check_version(installs:installs, fix:'116.0.5845.179', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
