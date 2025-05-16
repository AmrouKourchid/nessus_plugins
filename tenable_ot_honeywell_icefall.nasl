#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(500656);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/04");

  script_cve_id(
    "CVE-2022-30313",
    "CVE-2022-30314",
    "CVE-2022-30315",
    "CVE-2022-30316",
    "CVE-2022-30317"
  );

  script_name(english:"Honeywell Safety Manager Missing Authentication For Critical Function (CVE-2022-30313, CVE-2022-30314, CVE-2022-30315, CVE-2022-30316, CVE-2022-30317)");

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
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-22-207-02");
  script_set_attribute(attribute:"see_also", value:"https://www.forescout.com/research-labs/ot-icefall/");
  script_set_attribute(attribute:"solution", value:
"The following text was originally created by the Cybersecurity and Infrastructure Security Agency (CISA). The original
can be found at CISA.gov.

Honeywell recommends the following:

- For CVE-2022-30315 and CVE2022-30313: 
    - Safety Manager and FSC use a key switch control to prevent users from downloading unauthorized safety logic. When
the key switch is in the locked state, users cannot download any logic whatsoever.
    - Safety builder should reside on a station with restrictive access controls. Network controls should be in place to
limit the nodes permitted to communicate the builder protocol to the safety manager.
    - Users are advised to follow the Safety Manager release documentation.
- For CVE-2022-30314: 
    - Safety Manager R160.1 and later releases include a remediation for this item. R160.1 was introduced in October
2014. Users are advised to operate on the latest release and point release.
    - Customers should isolate process control networks following our security best practices.
    - Users are advised to follow the Safety Manager Release documentation; see the section “Security Recommendations
and Best Practices”.
- For CVE-2022-30316: 
    - The Safety Manager key switch prevents unauthorized firmware from being installed. Users are advised to monitor
the key switch position.
    - Users are advised to follow the Safety Manager Release documentation; see the section “Security Recommendations
and Best Practices”.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:honeywell:experion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Honeywell");

  exit(0);
}

include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Honeywell');

var asset = tenable_ot::assets::get(vendor:'Honeywell');

var vuln_cpes = {
    "cpe:/h:honeywell:experion" : {},
    "cpe:/h:honeywellprocess:experion" : {}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
