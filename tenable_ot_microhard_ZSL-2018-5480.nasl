#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(503148);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_xref(name:"ZSL", value:"2018-5480");

  script_name(english:"Microhard 3G/4G Cellular Ethernet and Serial Gateway Use of Default Credentials (ZSL-2018-5480)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OT asset is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The devices utilizes hard-coded credentials within its Linux
distribution image.
These sets of credentials are never exposed to the end-user and
cannot be changed through any normal operation of the gateway.
Another vulnerability could allow an authenticated attacker to gain
root access. The vulnerability is due to default credentials. An
attacker could exploit this vulnerability by logging in using the
default credentials.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/45040");
  script_set_attribute(attribute:"see_also", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5480.php");
  script_set_attribute(attribute:"solution", value:
"Refer to the vuln advisory.");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for unsupported products.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(1392);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:ipn3gb_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:ipn3gii_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:ipn4g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:ipn4gb_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:ipn4ii_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:bullet-3g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:bullet-lte_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:vip4gb_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:vip4g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:vip4g-wifi-n_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:bulletplus_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microhardcorp:dragon-lte_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Microhard");

  exit(0);
}


include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Microhard');

var asset = tenable_ot::assets::get(vendor:'Microhard');

var vuln_cpes = {
    "cpe:/o:microhardcorp:ipn3gb_firmware" : 
        {"versionEndIncluding" : "2.2.0-r2160", "versionStartIncluding" : "2.2.0-r2160", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:ipn3gii_firmware" : 
        {"versionEndIncluding" : "1.2.0-r1076", "versionStartIncluding" : "1.2.0-r1076", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:ipn4g_firmware" : 
        {"versionEndIncluding" : "1.1.0-r1098", "versionStartIncluding" : "1.1.0-r1098", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:ipn4gb_firmware:1.1.6" : 
        {"versionEndIncluding" : "1.1.6-r1184-14", "versionStartIncluding" : "1.1.6-r1184-14", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:ipn4gb_firmware:1.1.0" : 
        {"versionEndIncluding" : "1.1.0-r1090-2", "versionStartIncluding" : "1.1.0-r1090-2", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:ipn4gb_firmware:1.1.0rev2" : 
        {"versionEndIncluding" : "1.1.0-r1086", "versionStartIncluding" : "1.1.0-r1086", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:bullet-3g_firmware" : 
        {"versionEndIncluding" : "1.2.0-r1032", "versionStartIncluding" : "1.2.0-r1032", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:bullet-lte_firmware" : 
        {"versionEndIncluding" : "1.2.0-r1078", "versionStartIncluding" : "1.2.0-r1078", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:vip4gb_firmware" : 
        {"versionEndIncluding" : "1.1.6-r1204", "versionStartIncluding" : "1.1.6-r1204", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:vip4g_firmware" : 
        {"versionEndIncluding" : "1.1.6-r1184-14", "versionStartIncluding" : "1.1.6-r1184-14", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:vip4g-wifi-n_firmware" : 
        {"versionEndIncluding" : "1.1.6-r1196", "versionStartIncluding" : "1.1.6-r1196", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:bulletplus_firmware" : 
        {"versionEndIncluding" : "1.3.0-r1036", "versionStartIncluding" : "1.3.0-r1036", "family": "MicrohardCellularModem"},
    "cpe:/o:microhardcorp:dragon-lte_firmware" : 
        {"versionEndIncluding" : "1.1.0-r1036", "versionStartIncluding" : "1.1.0-r1036", "family": "MicrohardCellularModem"}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
