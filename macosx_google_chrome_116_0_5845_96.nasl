#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179838);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/18");

  script_cve_id(
    "CVE-2023-2312",
    "CVE-2023-4349",
    "CVE-2023-4350",
    "CVE-2023-4351",
    "CVE-2023-4352",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355",
    "CVE-2023-4356",
    "CVE-2023-4357",
    "CVE-2023-4358",
    "CVE-2023-4359",
    "CVE-2023-4360",
    "CVE-2023-4361",
    "CVE-2023-4362",
    "CVE-2023-4363",
    "CVE-2023-4364",
    "CVE-2023-4365",
    "CVE-2023-4366",
    "CVE-2023-4367",
    "CVE-2023-4368"
  );
  script_xref(name:"IAVA", value:"2023-A-0428-S");

  script_name(english:"Google Chrome < 116.0.5845.96 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 116.0.5845.96. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2023_08_stable-channel-update-for-desktop_15 advisory.

  - Use after free in Offline. (CVE-2023-2312)

  - Use after free in Device Trust Connectors. (CVE-2023-4349)

  - Inappropriate implementation in Fullscreen. (CVE-2023-4350, CVE-2023-4365)

  - Use after free in Network. (CVE-2023-4351)

  - Type Confusion in V8. (CVE-2023-4352)

  - Heap buffer overflow in ANGLE. (CVE-2023-4353)

  - Heap buffer overflow in Skia. (CVE-2023-4354)

  - Out of bounds memory access in V8. (CVE-2023-4355)

  - Use after free in Audio. (CVE-2023-4356)

  - Insufficient validation of untrusted input in XML. (CVE-2023-4357)

  - Use after free in DNS. (CVE-2023-4358)

  - Inappropriate implementation in App Launcher. (CVE-2023-4359)

  - Inappropriate implementation in Color. (CVE-2023-4360)

  - Inappropriate implementation in Autofill. (CVE-2023-4361)

  - Heap buffer overflow in Mojom IDL. (CVE-2023-4362)

  - Inappropriate implementation in WebShare. (CVE-2023-4363)

  - Inappropriate implementation in Permission Prompts. (CVE-2023-4364)

  - Use after free in Extensions. (CVE-2023-4366)

  - Insufficient policy enforcement in Extensions API. (CVE-2023-4367, CVE-2023-4368)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/08/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?404ab584");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1448548");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1458303");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1454817");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1465833");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1452076");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1458046");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1464215");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1468943");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1449929");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1458911");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1466415");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1443722");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1462723");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1465230");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1316379");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1367085");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1406922");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1431043");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1450784");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1467743");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1467751");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 116.0.5845.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4368");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'116.0.5845.96', severity:SECURITY_HOLE, xss:FALSE, xsrf:FALSE);
