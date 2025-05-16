#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-14.
# This plugin is a duplicate of 196912.
##

include('compat.inc');

if (description)
{
  script_id(214267);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id(
    "CVE-2023-42893",
    "CVE-2024-23236",
    "CVE-2024-23251",
    "CVE-2024-23282",
    "CVE-2024-27796",
    "CVE-2024-27798",
    "CVE-2024-27799",
    "CVE-2024-27800",
    "CVE-2024-27801",
    "CVE-2024-27802",
    "CVE-2024-27804",
    "CVE-2024-27805",
    "CVE-2024-27806",
    "CVE-2024-27808",
    "CVE-2024-27810",
    "CVE-2024-27811",
    "CVE-2024-27813",
    "CVE-2024-27815",
    "CVE-2024-27816",
    "CVE-2024-27817",
    "CVE-2024-27818",
    "CVE-2024-27820",
    "CVE-2024-27821",
    "CVE-2024-27822",
    "CVE-2024-27823",
    "CVE-2024-27824",
    "CVE-2024-27825",
    "CVE-2024-27826",
    "CVE-2024-27827",
    "CVE-2024-27829",
    "CVE-2024-27830",
    "CVE-2024-27831",
    "CVE-2024-27832",
    "CVE-2024-27834",
    "CVE-2024-27836",
    "CVE-2024-27837",
    "CVE-2024-27838",
    "CVE-2024-27841",
    "CVE-2024-27842",
    "CVE-2024-27843",
    "CVE-2024-27844",
    "CVE-2024-27847",
    "CVE-2024-27848",
    "CVE-2024-27850",
    "CVE-2024-27851",
    "CVE-2024-27855",
    "CVE-2024-27856",
    "CVE-2024-27857",
    "CVE-2024-27884",
    "CVE-2024-27885",
    "CVE-2024-40771"
  );
  script_xref(name:"APPLE-SA", value:"120903");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 14.x < 14.5 Multiple Vulnerabilities (120903) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin is a duplicate of 196912.");
  script_set_attribute(attribute:"description", value:
"This plugin is a duplicate of 196912.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120903");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27855");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

exit(0, "This plugin is a duplicate of 196912.");
