#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-03-07.
# This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_134_0_6998_35.nasl (226073)
##

include('compat.inc');

if (description)
{
  script_id(226070);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/07");

  script_cve_id(
    "CVE-2025-1914",
    "CVE-2025-1915",
    "CVE-2025-1916",
    "CVE-2025-1917",
    "CVE-2025-1918",
    "CVE-2025-1919",
    "CVE-2025-1921",
    "CVE-2025-1922",
    "CVE-2025-1923"
  );
  script_xref(name:"IAVA", value:"2025-A-0143");

  script_name(english:"Google Chrome < 134.0.6998.36 Multiple Vulnerabilities (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_134_0_6998_35.nasl (226073)");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_134_0_6998_35.nasl (226073)");
  # https://chromereleases.googleblog.com/2025/03/stable-channel-update-for-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e22c0822");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/397731718");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/391114799");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/376493203");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/329476341");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/388557904");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/392375312");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/387583503");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/384033062");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/382540635");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1916");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

exit(0, "This plugin has been deprecated due to it being a duplicate check. Please use google_chrome_134_0_6998_35.nasl (226073)");
