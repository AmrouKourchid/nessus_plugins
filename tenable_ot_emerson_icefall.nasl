#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(500658);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/08");

  script_cve_id(
    "CVE-2022-30261",
    "CVE-2022-30266",
    "CVE-2022-30263",
    "CVE-2022-29962",
    "CVE-2022-29963",
    "CVE-2022-29964",
    "CVE-2022-29965"
  );

  script_name(english:"Emerson DeltaV Distributed Control System Use of Hard-Coded Credentials (CVE-2022-29962, CVE-2022-29963, CVE-2022-29964, CVE-2022-29965, CVE-2022-30261, CVE-2022-30263, CVE-2022-30266)");

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
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-22-181-03");
  script_set_attribute(attribute:"see_also", value:"https://www.forescout.com/research-labs/ot-icefall/");
  script_set_attribute(attribute:"solution", value:
"The following text was originally created by the Cybersecurity and Infrastructure Security Agency (CISA). The original
can be found at CISA.gov.

Emerson has provided the following mitigations or workarounds:

Emerson has corrected CVE-2022-29965 in all currently supported versions of DeltaV. For additional mitigations and
preventative measures, please see the Emerson Guardian Support Portal (login required).

Emerson has mitigated CVE-2022-29962, CVE-2022-29963, and CVE-2022-29964 in all currently supported versions of DeltaV.
Please see the Emerson Guardian Support Portal (login required) for more information.

Emerson corrected the Firmware image verification vulnerability in Version 14.3 and mitigated it in all other versions.
Please see the Emerson Guardian Support Portal (login required) for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29965");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_ocr1100");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_occ100");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:ovation_ocr400");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:roc_300");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:roc_800");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:dl_8000");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:pacsystems_rx7i");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emerson:pacsystems_rx3i");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Emerson");

  exit(0);
}

include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Emerson');

var asset = tenable_ot::assets::get(vendor:'Emerson');

var vuln_cpes = {
    "cpe:/h:emerson:ovation_ocr1100" :
        {"family" : "Ovation"},
    "cpe:/h:emerson:ovation_occ100" :
        {"family" : "Ovation"},
    "cpe:/h:emerson:ovation_ocr400" :
        {"family" : "Ovation"},
    "cpe:/h:emerson:roc_300" :
        {"family" : "ROC300"},
    "cpe:/h:emerson:roc_800" :
        {"family" : "ROC800"},
    "cpe:/h:emerson:dl_8000" :
        {"family" : "ROC800"},
    "cpe:/h:emerson:pacsystems_rx7i" : {},
    "cpe:/h:emerson:pacsystems_rx3i" : {},
    "cpe:/h:emerson:deltav" : {}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_WARNING);
