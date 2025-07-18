#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130274);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/16");

  script_cve_id(
    "CVE-2019-13699",
    "CVE-2019-13700",
    "CVE-2019-13701",
    "CVE-2019-13702",
    "CVE-2019-13703",
    "CVE-2019-13704",
    "CVE-2019-13705",
    "CVE-2019-13706",
    "CVE-2019-13707",
    "CVE-2019-13708",
    "CVE-2019-13709",
    "CVE-2019-13710",
    "CVE-2019-13711",
    "CVE-2019-13713",
    "CVE-2019-13714",
    "CVE-2019-13715",
    "CVE-2019-13716",
    "CVE-2019-13717",
    "CVE-2019-13718",
    "CVE-2019-13719",
    "CVE-2019-15903"
  );

  script_name(english:"Google Chrome < 78.0.3904.70 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote macOS host is prior to 78.0.3904.70. It is, therefore, affected by
multiple vulnerabilities as referenced in the 2019_10_stable-channel-update-for-desktop_22 advisory. Note that Nessus
has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://chromereleases.googleblog.com/2019/10/stable-channel-update-for-desktop_22.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f325e8e");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1001503");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/998431");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/998284");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/991125");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/992838");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1001283");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/989078");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1001159");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/859349");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/931894");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1005218");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/756825");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/986063");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1004341");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/993288");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/982812");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/760855");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1005948");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/839239");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/866162");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/927150");
  script_set_attribute(attribute:"see_also", value:"https://crbug.com/1016016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Google Chrome version 78.0.3904.70 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-13700");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_google_chrome_installed.nbin");
  script_require_keys("MacOSX/Google Chrome/Installed");

  exit(0);
}
include('google_chrome_version.inc');

get_kb_item_or_exit('MacOSX/Google Chrome/Installed');

google_chrome_check_version(fix:'78.0.3904.70', severity:SECURITY_WARNING, xss:FALSE, xsrf:FALSE);
