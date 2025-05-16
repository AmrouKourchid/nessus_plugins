#TRUSTED 976735753f35b694eb08e6dc0127050650ba8792b60937ea6e58e0a1ddc447f012b10f2db4d337d1a89951a644c0a2bd8646d7152d4c8a0ecbac6ba29b92fa4fa5b5aedcb23f7cdad135edc829d7e593d45061002fc3cd8da1fbfe9a66e089fea99cee0a503c21cae295b97805939281ae11b6227f35033023f3ac2c71379fe9f614d2c7b8afa2a9cee0c847ce96ec3146b01b2a93a6bdb664a9f77a4b392fa63685676ecf53999ed96efb7b862d8d196ebaf34eb0a236a36f7bd471d294f445151b6ef30a9eeed6bd73810211bd168c74dacc76933d1af41a911d3a2db708725fa7df35cb32f00ba02f4e1ad279c44a2eb2f3abc3adf1f527044ccff15d6e4e40aafc80bdec46821bf66a7c285edc6f6d8d8b11797147d33c80f162a8b9a3bbdff716d3312d5361cb348d113fa9be8ae88ca93b1d1db8603e25fc3a8abae5f78bc45947b3a3a30e864bdde2067e792c756df0f99bffe8375dacf18fe0c96047c40f03b2fc9b42aeeb4f44939c8ea4cf639e65925ab931f2f4f8f6641f58f8c17e1be686d775ccd5657ef618688d47e97058f14769eaf90ead06541d1fc6de7104e1078d5e7a1681470387a2b8d1a0cff87d4aedb5f45a5ef8f83025d7ec234e1946ea039a07d0be57846296dd83885e1c9e5960cac9fa9ed0aaad54355b919f695411414a4221279d9f5db1773bf9ae78436fd24638369a107f3e21998c2180
#TRUST-RSA-SHA256 81349209f8237ed3f3cefe8e05e06b02f3865d8db3ed3844b1990715d6f17e4110704e56fa362808d5caca8900ef1dc0a3d30980d3a3df8a3af2eeb4f784a96785a591698466797d67537dfa60ccf260dcf4a87f02714fc6b84fb750f731f44048f5c9139f699931e16970995c5c29a624619a763f99450998d6ac9ad77544d7a49ae6fbe79260e6497950a57d0b207b17082d67d56933bee81b0aeafc2dde7a328e02454e6f84b4f9722ae2a8aac454dc21c29be9792944a188de12630c4ec1a5ee477023a2a83a1b43d14abed1a51f58ebf05c619c4234100e89878236e0ba4ba1388bf673e4585daabeb83fe3e7b1c15bce902dce19cb1238115d307ac4ce351812c8e343ab8b052434e28b8c38ea8186bbb560d505be488bba27f3f8eb1d01d24ea2358958a7e6be842b4ff083260f0661c9691108016216762803c4699d606514bbd7714d7b568c16ef7764af465b448c1207711ec5779ab28ec001be7b8dc2e73bc79767916c48786f6bcfdac450dd626109a920ce6c0a8aa9dbf2585312c82923b7571f52fa22555bb711a4376a3fa410f115750c34531ff0163aac70c4ceaa310e94c41d716ebc82e23b0e3c34556f803063261d45ff6881446549e7f0f1b0ead3369993cde1f59c7cdc0baad8b7ab8aeb52c0ba21a9ff4fc1af7ddade7592f600dd153f698aa16efc1412d27232fcf3905344b5cf4a3de750cdc6cd
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140186);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-3415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr89315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-dme-rce-cbE3nhZS");
  script_xref(name:"IAVA", value:"2020-A-0394-S");

  script_name(english:"Cisco NX-OS Software (UCS) Data Management Engine Remote Code Execution (cisco-sa-nxos-dme-rce-cbE3nhZS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software (UCS) is affected by a remote code execution vulnerability.
The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a
crafted Cisco Discovery Protocol packet to a Layer 2-adjacent affected device. A successful exploit could allow the
attacker to execute arbitrary code with administrative privileges or cause the Cisco Discovery Protocol process to
crash and restart multiple times, causing the affected device to reload and resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-dme-rce-cbE3nhZS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f83e12a0");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74239");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs10167");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvr89315");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_manager_version.nasl");
  script_require_keys("installed_sw/cisco_ucs_manager", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('cisco_func.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app = 'cisco_ucs_manager';

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
version = tolower(install['version']);

if ( cisco_gen_ver_compare(a:version, b:'4.0') >= 0 &&
      cisco_gen_ver_compare(a:version, b:'4.0(4h)') < 0
   )

{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : See vendor advisory' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}

audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Cisco UCS Manager', url, version);


