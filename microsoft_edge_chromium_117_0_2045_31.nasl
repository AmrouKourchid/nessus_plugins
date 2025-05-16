##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181483);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/01");

  script_cve_id(
    "CVE-2023-4863",
    "CVE-2023-4900",
    "CVE-2023-4901",
    "CVE-2023-4902",
    "CVE-2023-4903",
    "CVE-2023-4904",
    "CVE-2023-4905",
    "CVE-2023-4906",
    "CVE-2023-4907",
    "CVE-2023-4908",
    "CVE-2023-4909",
    "CVE-2023-36562",
    "CVE-2023-36727",
    "CVE-2023-36735"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/04");

  script_name(english:"Microsoft Edge (Chromium) < 117.0.2045.31 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 117.0.2045.31. It is, therefore, affected
by multiple vulnerabilities as referenced in the September 15, 2023 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-36562, CVE-2023-36735)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2023-36727)

  - Heap buffer overflow in WebP in Google Chrome prior to 116.0.5845.187 allowed a remote attacker to perform
    an out of bounds memory write via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-4863)

  - Inappropriate implementation in Custom Tabs in Google Chrome on Android prior to 117.0.5938.62 allowed a
    remote attacker to obfuscate a permission prompt via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4900)

  - Inappropriate implementation in Prompts in Google Chrome prior to 117.0.5938.62 allowed a remote attacker
    to potentially spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4901)

  - Inappropriate implementation in Input in Google Chrome prior to 117.0.5938.62 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4902)

  - Inappropriate implementation in Custom Mobile Tabs in Google Chrome on Android prior to 117.0.5938.62
    allowed a remote attacker to spoof security UI via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4903)

  - Insufficient policy enforcement in Downloads in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to bypass Enterprise policy restrictions via a crafted download. (Chromium security severity:
    Medium) (CVE-2023-4904)

  - Inappropriate implementation in Prompts in Google Chrome prior to 117.0.5938.62 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4905)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4906)

  - Inappropriate implementation in Intents in Google Chrome on Android prior to 117.0.5938.62 allowed a
    remote attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4907)

  - Inappropriate implementation in Picture in Picture in Google Chrome prior to 117.0.5938.62 allowed a
    remote attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4908)

  - Inappropriate implementation in Interstitials in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4909)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#september-15-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9a43f1");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36562");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36727");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36735");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4863");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4900");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4901");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4902");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4903");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4904");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4905");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4906");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4907");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4908");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-4909");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 117.0.2045.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4863");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '117.0.2045.31' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
