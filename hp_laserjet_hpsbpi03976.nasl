#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, inc.
##

include('compat.inc');

if (description)
{
  script_id(208683);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2024-9423");
  script_xref(name:"HP", value:"HPSBPI03976");
  script_xref(name:"IAVA", value:"2024-A-0616");

  script_name(english:"HP LaserJet Printers DoS (HPSBPI03976)");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Certain HP LaserJet printers may potentially experience a denial of service when a user sends a raw JPEG file to the 
printer. The printer displays a “JPEG Unsupported” message which may not clear, potentially blocking queued print jobs.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.hp.com/us-en/document/ish_11266441-11266463-16/hpsbpi03976
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1d80571");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the HP LaserJet firmware referenced in the
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9423");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_laserjet_detect.nasl");
  script_require_keys("www/hp_laserjet");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf_extras.inc');

var app_info = vcf::hp_laserjet::get_app_info(source:'fw');

var affected_models = make_list(
  '6GW99E',
  '9YF91E',
  '6GX00E',
  '6GX02E',
  '9YG02E',
  '6GX01A',
  '6GX05E',
  '9YG05E',
  '6GX09A',
  '6GX09E',
  '9YF96A',
  '9YF97A',
  '9YF98A',
  '9YG10A',
  '9YG11A',
  '6GX03A',
  '6GX04A',
  '6GX05A',
  '6GX06A',
  '6GW71A',
  '9YF90A',
  '6GW99A',
  '9YF88A',
  '9YF91A',
  '6GX00A',
  '9YF89A',
  '9YG02A',
  '9YF92A',
  '9YG05A',
  '9YF94A',
  '9YF95A',
  '9YG08A',
  '9YG09A',
  '9YF84A',
  '9YF85A',
  '6GW63A',
  '6GW61A',
  '6GW62A',
  '9YF80A',
  '9YF82A',
  '9YF83A',
  '6GW62E',
  '6GW62ER',
  '7MD69A',
  '7MD70A',
  '7MD70F',
  '2A129A',
  '7MD71A',
  '2A130A',
  '2U589A',
  '2U589F',
  '7MD72A',
  '7MD73A',
  '7MD74A',
  '7MD75A',
  '1Y7D4A',
  '7MD76A',
  '7MD70E',
  '2A130E',
  '2U589E',
  '7MD72E',
  '7MD74E',
  '7MD76E',
  '2U582A',
  '2U584A',
  '7MD66A',
  '7MD68A',
  '2U587A',
  '2U581A',
  '7MD65A',
  '7MD67A',
  '2U586A',
  '2U582E',
  '2U584E',
  '7MD66E',
  '7MD68E',
  '2U587E',
  '381U3A',
  '381U4A',
  '2R3E7A',
  '2R3E8A',
  '381L0A',
  '2R3F0A',
  '2R7F5A',
  '381U7A',
  '381U8A',
  '381V0A',
  '381V1A',
  '381U9A',
  '381U6A',
  '381U0A',
  '381U5A',
  '381U1A',
  '381U2A',
  '381V5A',
  '381V6A',
  '2R3E1A',
  '2R3E2A',
  '2R7F3A',
  '2R3E3A',
  '2R7F4A',
  '381V4A'
);

var constraints = [
  { 'models': affected_models, 'fixed_version': '20240813' }
];

vcf::hp_laserjet::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
