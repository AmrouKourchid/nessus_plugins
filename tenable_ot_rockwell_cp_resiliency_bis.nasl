#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(501228);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id("CVE-2023-3596");
  script_xref(name:"ICSA", value:"23-193-01");
  script_xref(name:"CEA-ID", value:"CEA-2023-0032");

  script_name(english:"Rockwell Automation Select Communication Modules Out-of-Bounds Write (CVE-2023-3596)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OT asset is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the 1756-EN4* products, it could allow a malicious
user to cause a denial of service by asserting the target system through
maliciously crafted CIP messages.

This plugin only works with Tenable.ot.
Please visit https://www.tenable.com/products/tenable-ot for more information.");
  # https://compatibility.rockwellautomation.com/Pages/MultiProductSelector.aspx?crumb=111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a39743bf");
  # https://rockwellautomation.custhelp.com/app/answers/answer_view/a_id/1140010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ba6a760");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01");
  # https://www.rockwellautomation.com/en-us/support/advisory.PN1633.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?943d08b7");
  script_set_attribute(attribute:"solution", value:
"The following text was originally created by the Cybersecurity and Infrastructure Security Agency (CISA). The original
can be found at CISA.gov.

Rockwell Automation has released the following versions to fix these vulnerabilities and can be addressed by performing
a standard firmware update. Customers are strongly encouraged to implement the risk mitigations provided below and to
the extent possible, to combine these with the security best practices to employ multiple strategies simultaneously.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4trk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en4trxt_series_a_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Tenable.ot");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_ot_api_integration.nasl");
  script_require_keys("Tenable.ot/Rockwell");

  exit(0);
}


include('tenable_ot_cve_funcs.inc');

get_kb_item_or_exit('Tenable.ot/Rockwell');

var asset = tenable_ot::assets::get(vendor:'Rockwell');

var vuln_cpes = {
    "cpe:/o:rockwellautomation:1756-en4tr_series_a_firmware:-" :
        {"versionEndExcluding" : "5.002", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4trk_series_a_firmware:-" :
        {"versionEndExcluding" : "5.002", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en4trxt_series_a_firmware:-" :
        {"versionEndExcluding" : "5.002", "family" : "ControlLogix"}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
