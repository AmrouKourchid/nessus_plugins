#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182419);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/23");

  script_cve_id(
    "CVE-2023-1999",
    "CVE-2023-5186",
    "CVE-2023-5187",
    "CVE-2023-5217"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/23");
  script_xref(name:"IAVA", value:"2023-A-0523-S");

  script_name(english:"Microsoft Edge (Chromium) < 116.0.1938.98 / 117.0.2045.47 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 116.0.1938.98 / 117.0.2045.47. It is,
therefore, affected by multiple vulnerabilities as referenced in the September 29, 2023 advisory.

  - There exists a use after free/double free in libwebp. An attacker can use the ApplyFiltersAndEncode()
    function and loop through to free best.bw and assign best = trial pointer. The second loop will then
    return 0 because of an Out of memory error in VP8 encoder, the pointer is still assigned to trial and the
    AddressSanitizer will attempt a double free. (CVE-2023-1999)

  - Use after free in Passwords in Google Chrome prior to 117.0.5938.132 allowed a remote attacker who
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via crafted
    UI interaction. (Chromium security severity: High) (CVE-2023-5186)

  - Use after free in Extensions in Google Chrome prior to 117.0.5938.132 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-5187)

  - Heap buffer overflow in vp8 encoding in libvpx in Google Chrome prior to 117.0.5938.132 and libvpx 1.13.1
    allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-5217)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#september-29-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f89fc291");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1999");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5186");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5187");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-5217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 116.0.1938.98 / 117.0.2045.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin", "smb_hotfixes.nasl");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< product_name)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (extended) {
	constraints = [
  		{ 'fixed_version' : '116.0.1938.98' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '117.0.2045.47' }
	];
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
