#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182436);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id(
    "CVE-2023-32361",
    "CVE-2023-32396",
    "CVE-2023-35074",
    "CVE-2023-35984",
    "CVE-2023-38596",
    "CVE-2023-40384",
    "CVE-2023-40391",
    "CVE-2023-40395",
    "CVE-2023-40399",
    "CVE-2023-40400",
    "CVE-2023-40403",
    "CVE-2023-40409",
    "CVE-2023-40410",
    "CVE-2023-40412",
    "CVE-2023-40414",
    "CVE-2023-40419",
    "CVE-2023-40420",
    "CVE-2023-40427",
    "CVE-2023-40429",
    "CVE-2023-40432",
    "CVE-2023-40448",
    "CVE-2023-40452",
    "CVE-2023-40454",
    "CVE-2023-40456",
    "CVE-2023-40520",
    "CVE-2023-40528",
    "CVE-2023-41063",
    "CVE-2023-41065",
    "CVE-2023-41068",
    "CVE-2023-41071",
    "CVE-2023-41073",
    "CVE-2023-41074",
    "CVE-2023-41174",
    "CVE-2023-41968",
    "CVE-2023-41981",
    "CVE-2023-41984"
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2023-09-26");
  script_xref(name:"APPLE-SA", value:"HT213936");
  script_xref(name:"IAVA", value:"2023-A-0529-S");

  script_name(english:"Apple TV < 17 Multiple Vulnerabilities (HT213936)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device is prior to 17. It is therefore affected by
multiple vulnerabilities as described in the HT213936");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213936");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41074");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-40414");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var fixed_build = '21J354';
var tvos_ver = '17';

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
