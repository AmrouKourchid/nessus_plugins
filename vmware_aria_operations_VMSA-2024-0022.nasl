#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212134);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id(
    "CVE-2024-38830",
    "CVE-2024-38831",
    "CVE-2024-38832",
    "CVE-2024-38833",
    "CVE-2024-38834"
  );
  script_xref(name:"VMSA", value:"2024-0022");
  script_xref(name:"IAVA", value:"2024-A-0768-S");

  script_name(english:"VMware Aria Operations Multiple Vulnerabilities (VMSA-2024-0022)");

  script_set_attribute(attribute:"synopsis", value:
"VMware Aria Operations running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Aria Operations running on the remote host is missing a vendor supplied patch. It is,
therefore, affected by multiple vulnerabilities:

  - VMware Aria Operations contains a privilege escalation vulnerability. A malicious actor with local administrative
    privileges may trigger this vulnerability to escalate privileges to root user on the appliance running VMware Aria
    Operations. (CVE-2024-38830)

  - VMware Aria Operations contains a privilege escalation vulnerability. A malicious actor with local administrative
    privileges may trigger this vulnerability to escalate privileges to root user on the appliance running VMware Aria
    Operations. (CVE-2024-38831)

  - VMware Aria Operations contains a stored cross-site scripting vulnerability. A malicious actor with editing
    access to views may be able to inject malicious script leading to stored cross-site scripting in the product
    VMware Aria Operations. (CVE-2024-38832)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25199
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea7c9215");
  script_set_attribute(attribute:"solution", value:
"Upgrade VMware Aria Operations to the version outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38830");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38831");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_operations");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vrealize_operations_manager_webui_detect.nbin");
  script_require_keys("installed_sw/vRealize Operations Manager");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'vRealize Operations Manager';
get_install_count(app_name:app, exit_if_zero:TRUE);

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

var constraints = [
  {'fixed_version':'8.18.2.24394060', 'fixed_display':'8.18.2 Build 24394060'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
