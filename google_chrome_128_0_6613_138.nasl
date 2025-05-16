#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-05.
# This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_128_0_6613_137.nasl (206911)
##

include('compat.inc');

if (description)
{
  script_id(206910);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id(
    "CVE-2024-8636",
    "CVE-2024-8637",
    "CVE-2024-8638",
    "CVE-2024-8639"
  );
  script_xref(name:"IAVA", value:"2024-A-0568-S");

  script_name(english:"Google Chrome < 128.0.6613.138 Multiple Vulnerabilities (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_128_0_6613_137.nasl (206911)");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_128_0_6613_137.nasl (206911)");
  # https://chromereleases.googleblog.com/2024/09/stable-channel-update-for-desktop_10.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e4eceac");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/361461526");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/361784548");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/362539773");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/362658609");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

exit(0, "This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_128_0_6613_137.nasl (206911)");
