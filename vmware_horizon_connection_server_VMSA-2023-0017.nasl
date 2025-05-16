#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179665);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2023-34037", "CVE-2023-34038");
  script_xref(name:"IAVA", value:"2023-A-0399");

  script_name(english:"VMware Horizon Server < 2111.2 / < 2209.1 / < 2212.1 / < 2306 Multiple Vulnerabilities (VMSA-2023-0017)");

  script_set_attribute(attribute:"synopsis", value:
"A virtual desktop connection manager installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon Server installed on the remote Windows host is prior to 2111.2, 2206 or 2209 prior to 
2209.1, 2212 prior to 2212.1 or 2023. It is, therefore affected by multiple vulnerabilities:

 - An HTTP request smuggling vulnerability whereby malicious actor with network access may be able to perform
   HTTP smuggle requests. (CVE-2023-34037)

 - An information disclosure vulnerability whereby a malicious actor with network access may be able to
   access information relating to the internal network configuration. (CVE-2023-34038)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2023-0017.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMWare Horizon Server 2111.2, 2209.1, 2212.1, 2023 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-34038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'VMware Horizon View', win_local:TRUE);

# need to filter out the agent as connection server only resides on the server
if (! empty_or_null(app_info['Install type']) && app_info['Install type'] =='Agent'  ) audit(AUDIT_INST_VER_NOT_VULN, 'VMWare Horizon Agent');

# Versions can be mapped with https://customerconnect.vmware.com/en/downloads/info/slug/desktop_end_user_computing/vmware_horizon
var constraints = [
  { 'min_version': '8.0.0', 'fixed_version': '8.4.2', 'fixed_display': '8.4.2 (2111.2)'},
  { 'min_version': '8.6.0', 'fixed_version': '8.7.1', 'fixed_display': '8.7.1 (2209.1)'},
  { 'min_version': '8.8.0', 'fixed_version': '8.8.1', 'fixed_display': '8.8.1 (2212.1)'},
  { 'min_version': '8.9.0', 'fixed_version': '8.10.0', 'fixed_display': '8.10.0 (2306)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

