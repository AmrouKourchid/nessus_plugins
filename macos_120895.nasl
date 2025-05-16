#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-03-20.
# This plugin is a duplicate of 191713.
##

include('compat.inc');

if (description)
{
  script_id(215231);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id(
    "CVE-2022-42816",
    "CVE-2022-48554",
    "CVE-2023-42853",
    "CVE-2023-48795",
    "CVE-2023-51384",
    "CVE-2023-51385",
    "CVE-2024-0258",
    "CVE-2024-23205",
    "CVE-2024-23216",
    "CVE-2024-23225",
    "CVE-2024-23226",
    "CVE-2024-23227",
    "CVE-2024-23229",
    "CVE-2024-23230",
    "CVE-2024-23231",
    "CVE-2024-23232",
    "CVE-2024-23233",
    "CVE-2024-23234",
    "CVE-2024-23235",
    "CVE-2024-23238",
    "CVE-2024-23239",
    "CVE-2024-23241",
    "CVE-2024-23242",
    "CVE-2024-23244",
    "CVE-2024-23245",
    "CVE-2024-23246",
    "CVE-2024-23247",
    "CVE-2024-23248",
    "CVE-2024-23249",
    "CVE-2024-23250",
    "CVE-2024-23253",
    "CVE-2024-23254",
    "CVE-2024-23255",
    "CVE-2024-23257",
    "CVE-2024-23258",
    "CVE-2024-23259",
    "CVE-2024-23260",
    "CVE-2024-23261",
    "CVE-2024-23263",
    "CVE-2024-23264",
    "CVE-2024-23265",
    "CVE-2024-23266",
    "CVE-2024-23267",
    "CVE-2024-23268",
    "CVE-2024-23269",
    "CVE-2024-23270",
    "CVE-2024-23272",
    "CVE-2024-23273",
    "CVE-2024-23274",
    "CVE-2024-23275",
    "CVE-2024-23276",
    "CVE-2024-23277",
    "CVE-2024-23278",
    "CVE-2024-23279",
    "CVE-2024-23280",
    "CVE-2024-23281",
    "CVE-2024-23283",
    "CVE-2024-23284",
    "CVE-2024-23285",
    "CVE-2024-23286",
    "CVE-2024-23287",
    "CVE-2024-23288",
    "CVE-2024-23289",
    "CVE-2024-23290",
    "CVE-2024-23291",
    "CVE-2024-23292",
    "CVE-2024-23293",
    "CVE-2024-23294",
    "CVE-2024-23296",
    "CVE-2024-23299",
    "CVE-2024-27789",
    "CVE-2024-27792",
    "CVE-2024-27809",
    "CVE-2024-27853",
    "CVE-2024-27859",
    "CVE-2024-27886",
    "CVE-2024-27887",
    "CVE-2024-27888",
    "CVE-2024-54658"
  );
  script_xref(name:"APPLE-SA", value:"120895");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/03/27");

  script_name(english:"macOS 14.x < 14.4 Multiple Vulnerabilities (120895) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin is a duplicate of 191713.");
  script_set_attribute(attribute:"description", value:
"This plugin is a duplicate of 191713.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/120895");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27859");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:14.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

exit(0, "This plugin is a duplicate of 191713.");
