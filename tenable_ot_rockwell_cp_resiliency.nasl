##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(501226);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id("CVE-2023-3595");
  script_xref(name:"ICSA", value:"23-193-01");
  script_xref(name:"CEA-ID", value:"CEA-2023-0032");

  script_name(english:"Rockwell Automation Select Communication Modules Out-of-Bounds Write (CVE-2023-3595)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OT asset is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the 1756 EN2* and 1756 EN3* products, it could
allow a malicious user to perform remote code execution with persistence on the
target system through maliciously crafted CIP messages. This includes the
ability to modify, deny, and exfiltrate data passing through the device.

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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3595");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2t_series_d_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tk_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tk_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tk_series_d_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2txt_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2txt_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2txt_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2txt_series_d_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tp_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tpk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tpxt_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2tr_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trk_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trk_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trxt_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trxt_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2trxt_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2f_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2f_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2f_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2fk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2fk_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en2fk_series_c_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3tr_series_b_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3trk_series_a_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rockwellautomation:1756-en3trk_series_b_firmware");
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
    "cpe:/o:rockwellautomation:1756-en2t_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_c_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_c_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2t_series_d_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_c_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_c_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tk_series_d_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_c_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_c_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2txt_series_d_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tp_series_a_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tpk_series_a_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tpxt_series_a_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2tr_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trk_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trk_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trk_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trk_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trk_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trxt_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trxt_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trxt_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trxt_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2trxt_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2f_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2fk_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2fk_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2fk_series_b_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2fk_series_b_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en2fk_series_c_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3tr_series_b_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3trk_series_a_firmware:5.009" :
        {"versionEndIncluding" : "5.008", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3trk_series_a_firmware:5.029" :
        {"versionEndIncluding" : "5.028", "versionStartIncluding": "5.028", "family" : "ControlLogix"},
    "cpe:/o:rockwellautomation:1756-en3trk_series_b_firmware:-" :
        {"versionEndIncluding" : "11.003", "family" : "ControlLogix"}
};

tenable_ot::cve::compare_and_report(asset:asset, cpes:vuln_cpes, severity:SECURITY_HOLE);
