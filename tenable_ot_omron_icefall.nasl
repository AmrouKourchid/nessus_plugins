#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(500657);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/04");

  script_cve_id("CVE-2022-31204", "CVE-2022-31207");

  script_name(english:"Omron SYSMAC CS/CJ/CP Series and NJ/NX Series Cleartext Transmission of Sensitive Information (CVE-2022-31204, CVE-2022-31207)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OT asset may be affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The device may be vulnerable to flaws related to OT:ICEFALL. These vulnerabilities
identify the insecure-by-design nature of OT devices and may not have a clear
remediation path. As such, Nessus is unable to test specifically for these
vulnerabilities but has identified the device to be one that was listed in the
OT:ICEFALL report. Ensure your OT deployments follow best practices including
accurate inventory, separation of environments, and monitoring. This plugin will
trigger on any device seen by Tenable.OT that matches a family or model listed
in the OT:ICEFALL report.

Note: All findings need to be manually verified based on the advisory from the vendor, once released.

This plugin only works with Tenable.ot. Please visit
https://www.tenable.com/products/tenable-ot for more information.");
  # https://www.cisa.gov/uscert/ncas/current-activity/2022/06/22/cisa-releases-security-advisories-related-oticefall-insecure
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4901fbd6");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-22-179-02");
  script_set_attribute(attribute:"see_also", value:"https://www.forescout.com/research-labs/ot-icefall/");
  script_set_attribute(attribute:"solution", value:
"The following text was originally created by the Cybersecurity and Infrastructure Security Agency (CISA). The original
can be found at CISA.gov.

 For CVE-2022-31204: Omron recommends users implement an extended password protection function in the following product
versions:

- CS1, v.4.1 or later 
- CJ2M, v2.1 or later 
- CJ2H, v1.5 or later
- CP1E/CP1H , v1.30 or later
- CP1L, v1.10 or later 
- CX-Programmer, v9.6 or higher

For CVE-2022-31206: Omron intends to publish an update for SYSMAC NJ/NX in July 2022.

For CVE-2022-31207: Omron recommends users of SYSMAC CS/CJ/CP Series to use the PLC protection password and enable
protection against unauthorized write access to address. Also, there are hardware DIP switches on the PLC which can
prevent unauthorized PLC program changes regardless of password.

For CVE-2022-31205: Omron recommends using different passwords between the CP1W-CIF41 Ethernet Option Board and CP1 PLC
itself. The Web UI password will not grant access to the PLC.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:omron:cj2h_plc");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:omron:cj2m_plc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:omron:sysmac_cp1e_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:omron:sysmac_cp1h_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:omron:sysmac_cp1l_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Omron");

  exit(0);
}

include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Omron');

var asset = tenable_ot::assets::get(vendor:'Omron');

var vuln_cpes = {
    "cpe:/h:omron:cj2h_plc" :
        {"versionEndExcluding" : "1.5", "family" : "CJ2H"},
    "cpe:/h:omron:cj2m_plc" :
        {"versionEndExcluding" : "2.1", "family" : "CJ2M"},
    "cpe:/o:omron:sysmac_cp1e_firmware" :
        {"versionEndExcluding" : "1.30", "family" : "CP"},
    "cpe:/o:omron:sysmac_cp1h_firmware" :
        {"versionEndExcluding" : "1.30", "family" : "CP"},
    "cpe:/o:omron:sysmac_cp1l_firmware" :
        {"versionEndExcluding" : "1.10", "family" : "CP"}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
