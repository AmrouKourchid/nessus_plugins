#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200520);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2022-22675",
    "CVE-2022-23308",
    "CVE-2022-26700",
    "CVE-2022-26701",
    "CVE-2022-26702",
    "CVE-2022-26706",
    "CVE-2022-26708",
    "CVE-2022-26709",
    "CVE-2022-26710",
    "CVE-2022-26711",
    "CVE-2022-26714",
    "CVE-2022-26716",
    "CVE-2022-26717",
    "CVE-2022-26719",
    "CVE-2022-26724",
    "CVE-2022-26736",
    "CVE-2022-26737",
    "CVE-2022-26738",
    "CVE-2022-26739",
    "CVE-2022-26740",
    "CVE-2022-26745",
    "CVE-2022-26757",
    "CVE-2022-26763",
    "CVE-2022-26764",
    "CVE-2022-26765",
    "CVE-2022-26766",
    "CVE-2022-26768",
    "CVE-2022-26771",
    "CVE-2022-26775",
    "CVE-2022-26776",
    "CVE-2022-32790"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2024-06-04");
  script_xref(name:"APPLE-SA", value:"HT213254");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");

  script_name(english:"Apple TV < 15.5 Multiple Vulnerabilities (HT213254)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 15.5. It is therefore affected by
multiple vulnerabilities as described in the HT213254");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213254");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 15.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26771");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include('appletv_func.inc');

var url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
var port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

var build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

var model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

var fixed_build = '19L570';
var tvos_ver = '15.5';

# determine gen from the model
var gen = APPLETV_MODEL_GEN[model];

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  affected_gen   : make_list(4, 5, 6),
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE
);
