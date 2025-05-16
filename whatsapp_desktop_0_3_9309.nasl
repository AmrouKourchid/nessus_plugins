#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197073);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/16");

  script_cve_id("CVE-2019-18426");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"WhatsApp Desktop < 0.3.9309 Persistent Cross-Site Scripting (CVE-2019-18426)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a persistent cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WhatsApp Desktop installed on the remote Windows host is prior to 0.3.9309. It is, therefore,
affected by a persistent cross-site scripting vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.whatsapp.com/security/advisories/archive");
  # http://packetstormsecurity.com/files/157097/WhatsApp-Desktop-0.3.9308-Cross-Site-Scripting.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f434b5a3");
  script_set_attribute(attribute:"see_also", value:"https://github.com/weizman/CVE-2019-18426");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WhatsApp Desktop 0.3.9309 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18426");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:whatsapp:whatsapp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("whatsapp_desktop_win_installed.nbin");
  script_require_keys("installed_sw/WhatsApp Desktop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'WhatsApp Desktop', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '0.3.9309' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
