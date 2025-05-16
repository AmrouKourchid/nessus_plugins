#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192109);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2024-2049");
  script_xref(name:"IAVA", value:"2024-A-0164");

  script_name(english:"Citrix SD-WAN 11.4.x < 11.4.4.46 (CTX617071)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix SD-WAN installed on the remote host is prior to 11.4.4.46. It is, therefore, affected by a
vulnerability as referenced in the CTX617071 advisory.

  - Server-Side Request Forgery (SSRF) in Citrix SD-WAN Standard/Premium Editions on or after 11.4.0 and
    before 11.4.4.46 allows an attacker to disclose limited information from the appliance via Access to
    management IP. (CVE-2024-2049)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.citrix.com/article/CTX617071/citrix-sdwan-security-bulletin-for-cve20242049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3f76937");
  script_set_attribute(attribute:"solution", value:
"Upgrade Citrix SD-WAN based upon the guidance specified in CTX617071.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Citrix SD-WAN');

if (!empty_or_null(app_info.Edition) && 'Standard' >!< app_info.Edition && 'Premium' >!< app_info.Edition)
  vcf::audit(app_info);

var constraints = [
  { 'min_version' : '11.4.0', 'fixed_version' : '11.4.4.46' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
