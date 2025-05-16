#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185545);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/21");

  script_cve_id("CVE-2023-39205");

  script_name(english:"Zoom VDI Meeting Client < 5.16.0 Vulnerability (ZSB-23049)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom VDI Meeting Client installed on the remote host is prior to 5.16.0. It is, therefore, affected by a
vulnerability as referenced in the ZSB-23049 advisory.

  - Improper conditions check in Zoom Team Chat for Zoom clients may allow an authenticated user to conduct a
    denial of service via network access. Users can help keep themselves secure by applying current updates or
    downloading the latest Zoom software with all current security updates from https://zoom.us/download.
    (CVE-2023-39205)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-23049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f5586d0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom VDI Meeting Client 5.16.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39205");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for VDI");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

app_info = vcf::get_app_info(app:'Zoom Client for VDI', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '5.16.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
