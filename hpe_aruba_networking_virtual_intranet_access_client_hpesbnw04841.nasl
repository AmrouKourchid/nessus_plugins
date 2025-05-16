#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233997);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2024-3661", "CVE-2025-25041");
  script_xref(name:"IAVA", value:"2025-B-0047");

  script_name(english:"HPE Aruba Networking Virtual Intranet Access (VIA) Client < 4.7.2 Multiple Vulnerabilities (hpesbnw04841)");

  script_set_attribute(attribute:"synopsis", value:
"The remote HPE Aruba Networking Virtual Intranet Access (VIA) Client is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of HPE Aruba Networking Virtual Intranet Access (VIA) Client running on the remote host is affected by
multiple vulnerabilities, as referenced in the hpesbnw04841 advisory. 

  - DHCP can add routes to a client’s routing table via the classless static route option (121). VPN-based
    security solutions that rely on routes to redirect traffic can be forced to leak traffic over the physical
    interface. An attacker on the same local network can read, disrupt, or possibly  modify network traffic
    that was expected to be protected by the VPN. (CVE-2024-3661)

  - [Windows only] A vulnerability in the HPE Aruba Networking Virtual Intranet Access (VIA) client could
    allow malicious users to overwrite arbitrary files as NT AUTHORITY\SYSTEM (root). A successful exploit
    could allow the creation of a Denial-of-Service (DoS) condition affecting the Microsoft Windows Operating
    System. This vulnerability does not affect Linux and Android based clients. (CVE-2025-25041)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04841en_us&docLocale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64b63dc1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HPE Aruba Networking Virtual Intranet Access (VIA) Client version 4.7.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3661");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:aruba_virtual_intranet_access");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hpe_aruba_networking_virtual_intranet_access_client_win_installed.nbin", "hpe_aruba_networking_virtual_intranet_access_client_macos_installed.nbin", "hpe_aruba_networking_virtual_intranet_access_client_nix_installed.nbin");
  script_require_keys("installed_sw/HPE Aruba Networking Virtual Intranet Access (VIA) Client");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
      {
        'product':{'name': 'HPE Aruba Networking Virtual Intranet Access (VIA) Client', 'type': 'app'},
        'check_algorithm': 'default',
        'constraints': [
          {
            'requires': [{'scope': 'target', 'match': {'os': 'windows'}}],
            'fixed_version':'4.7.1', 'fixed_display':'4.7.2',
            'report': {'cves': ['CVE-2024-3661', 'CVE-2025-25041']}
          },
          {
            'requires': [{'scope': 'target', 'match_one': {'os': ['macos', 'linux']}}],
            'fixed_version':'4.7.1', 'fixed_display':'4.7.2',
            'report': {'cves': ['CVE-2024-3661']}
          }
        ]
      }
    ]
  };

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);

