#TRUSTED 0c9563cbfc22932fc0f4b045f3d04e1cfe33b04ba930d4a05a8be812430d25e98689be6d02d2208255bc5c4c368d1f5ca9be42cc494804228d390cc7a7b221626a18c4027ad82a0d425f5624f51fabf4dd04736e1d4ec64c27780a40ec6032b7b7f01aeaf9b2015843dc9c3f54d1443d049462b239a09c3aad573c52da5e05157c763d2ec22fbfab34ab85442a5f9c7a79394ac84a1037cd0a97a59d45da5742b152a40ab7d065b0b111465902a28bc364209b1bbb16368c2d261f10fb56d7cdfb9428cdac9477057f6371caa4c9593e7f2cccd8b2e23fba3e19d4d6269218278414b0034eaee9de6964b83a7a15067c7ee153ad1547e4e7a7ac763c85ff31cda7d3a4fe050b77051c4c0cb8e81f5931d3ced21817f5626f51cae7e38c32d523872c73764dbc2ec016c2f5b25fc539001ddfaba22485f17725c95b82743a1f35be3ba6dc8bb881d816a4aca1450d49d8d370ff1113d6ae040568d202110210e1645dc782bf1f033a3d2688b2e8b3b019b18db919469a28e51d84baff87d0520f154d4b48ed1b9386600a138d8decc33e48eae1c7a83204e19fc939f957cafd79f44ff3381de815a8ba938e312b1e096abba9acfcf33858807629f1f14d7a39a90479c3d1ea547e505f2e97326a0ff37d1318acf2f84d977bf86d69fbb71c7c26532af0f92476457c9d7388dcada8c1ecefdd4f818b44c6d341c5b9d530a5c66d
#TRUST-RSA-SHA256 563a653389959aa9720cfb03680442cf540e3a1b71ae32a9bc7869ac9a9ca205354741e4b60242f8c456e90626b7a89e38dcd5a83f9ca5965d1e4c4ec4ce52e89a98723e03dcbb86eae8285bdba47fb858de1c26ad19b437f71db096f2e39ccd1dd8afe99436b78a3b82c5ed2111251a6e2ea948d12a5137858125af7a28a1c489850bafc110312889e0810abc384c6fac07de5b47f22c4aa8ec4c1dbec4d788b0cf78db6d86a96fa42a54cae71c081d9e5cdf186c3939bf04035dbba836a4a074d0f1ed0a20180b9147f40f9317fcaf67463a6710110f9878be3e8db073706ebe32038a65780300834aa3cdbd0fce97aba0181a44c678ae18b0679dccbd326ef1b6d9b7deb2f85a3c05ada9cdf7e611a82f8238412a10537cbd991c0d4ca0662a767767987b6641392ab8bacc3e87d93a7bfce8e7470175ffadd58b28753451d5599c404ab861fbd739ec639cc8d6f9519353b1a7455b08598e72d1787f9b5f6830d4cc0374383ede673143097af243e822c98caa2a14241c95e3f66e7cf0cde3e79720cb5f19095149b994753f9c4e7728266fb1826906ac1d9da6e1fd852e3ffba31b03b5218c29f25428e81b70f88b48498231e9ed6ec29169165d87b07fb3f20428c434c5790d615053b2629d29a82121b76ca088690777760e07c6faf3b55e5790aba4294b760b302075ec3986d8603e2fe1d090e84b594689210e743d
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101269);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id(
    "CVE-2017-6736",
    "CVE-2017-6737",
    "CVE-2017-6738",
    "CVE-2017-6739",
    "CVE-2017-6740",
    "CVE-2017-6741",
    "CVE-2017-6742",
    "CVE-2017-6743",
    "CVE-2017-6744"
  );
  script_bugtraq_id(99345);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve54313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve57697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60376");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60402");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve60507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66540");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve66658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve78027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve89865");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170629-snmp");
  script_xref(name:"IAVA", value:"2017-A-0191-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/10");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Cisco IOS XE SNMP Packet Handling Remote Buffer Overflow Multiple RCE (cisco-sa-20170629-snmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by multiple
remote code execution vulnerabilities in the Simple Network Management
Protocol (SNMP) subsystem due to multiple buffer overflow conditions.
An unauthenticated, remote attacker can exploit these vulnerabilities,
via a specially crafted SNMP packet, to execute arbitrary code.

To exploit these vulnerabilities via SNMP version 2c or earlier, the
attacker must know the SNMP read-only community string for the
affected system. To exploit these vulnerabilities via SNMP version 3,
the attacker must have user credentials for the affected system.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170629-snmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?564e08f8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve54313");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve57697");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60376");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60402");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve60507");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66540");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66601");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve66658");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve78027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve89865");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security
Advisory cisco-sa-20170629-snmp. Alternatively, as a workaround,
disable the following MIBs on the device :

  - ADSL-LINE-MIB
  - ALPS-MIB
  - CISCO-ADSL-DMT-LINE-MIB
  - CISCO-BSTUN-MIB
  - CISCO-MAC-AUTH-BYPASS-MIB
  - CISCO-SLB-EXT-MIB
  - CISCO-VOICE-DNIS-MIB
  - CISCO-VOICE-NUMBER-EXPANSION-MIB
  - TN3270E-RT-MIB");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6744");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check for vuln versions
if (
  ver == '2.2.0' ||
  ver == '2.2.1' ||
  ver == '2.2.2' ||
  ver == '2.2.3' ||
  ver == '2.3.0' ||
  ver == '2.3.1' ||
  ver == '2.3.1t' ||
  ver == '2.3.2' ||
  ver == '2.4.0' ||
  ver == '2.4.1' ||
  ver == '2.4.2' ||
  ver == '2.4.3' ||
  ver == '2.5.0' ||
  ver == '2.5.1' ||
  ver == '2.6.0' ||
  ver == '2.6.1' ||
  ver == '3.1.0S' ||
  ver == '3.1.1S' ||
  ver == '3.1.2S' ||
  ver == '3.1.3aS' ||
  ver == '3.1.4S' ||
  ver == '3.1.4aS' ||
  ver == '3.10.0S' ||
  ver == '3.10.1S' ||
  ver == '3.10.1xbS' ||
  ver == '3.10.2S' ||
  ver == '3.10.2tS' ||
  ver == '3.10.3S' ||
  ver == '3.10.4S' ||
  ver == '3.10.5S' ||
  ver == '3.10.6S' ||
  ver == '3.10.7S' ||
  ver == '3.10.8S' ||
  ver == '3.10.8aS' ||
  ver == '3.11.0S' ||
  ver == '3.11.1S' ||
  ver == '3.11.2S' ||
  ver == '3.11.3S' ||
  ver == '3.11.4S' ||
  ver == '3.12.0S' ||
  ver == '3.12.1S' ||
  ver == '3.12.2S' ||
  ver == '3.12.3S' ||
  ver == '3.12.4S' ||
  ver == '3.13.0S' ||
  ver == '3.13.0aS' ||
  ver == '3.13.1S' ||
  ver == '3.13.2S' ||
  ver == '3.13.3S' ||
  ver == '3.13.4S' ||
  ver == '3.13.5S' ||
  ver == '3.13.6S' ||
  ver == '3.13.6aS' ||
  ver == '3.14.0S' ||
  ver == '3.14.1S' ||
  ver == '3.14.2S' ||
  ver == '3.14.3S' ||
  ver == '3.14.4S' ||
  ver == '3.15.0S' ||
  ver == '3.15.1S' ||
  ver == '3.15.1cS' ||
  ver == '3.15.2S' ||
  ver == '3.15.3S' ||
  ver == '3.15.4S' ||
  ver == '3.16.0S' ||
  ver == '3.16.0cS' ||
  ver == '3.16.1S' ||
  ver == '3.16.2S' ||
  ver == '3.16.3S' ||
  ver == '3.16.4S' ||
  ver == '3.16.4bS' ||
  ver == '3.16.5S' ||
  ver == '3.17.0S' ||
  ver == '3.17.1S' ||
  ver == '3.2.0S' ||
  ver == '3.2.0SE' ||
  ver == '3.2.1S' ||
  ver == '3.2.2S' ||
  ver == '3.3.0S' ||
  ver == '3.3.0SE' ||
  ver == '3.3.1S' ||
  ver == '3.3.2S' ||
  ver == '3.4.0S' ||
  ver == '3.4.0aS' ||
  ver == '3.4.1S' ||
  ver == '3.4.2S' ||
  ver == '3.4.3S' ||
  ver == '3.4.4S' ||
  ver == '3.4.5S' ||
  ver == '3.4.6S' ||
  ver == '3.5.0S' ||
  ver == '3.5.1S' ||
  ver == '3.5.2S' ||
  ver == '3.6.0S' ||
  ver == '3.6.1S' ||
  ver == '3.6.2S' ||
  ver == '3.7.0S' ||
  ver == '3.7.1S' ||
  ver == '3.7.2S' ||
  ver == '3.7.3S' ||
  ver == '3.7.4S' ||
  ver == '3.7.4aS' ||
  ver == '3.7.5S' ||
  ver == '3.7.6S' ||
  ver == '3.7.7S' ||
  ver == '3.8.0EX' ||
  ver == '3.8.0S' ||
  ver == '3.8.1S' ||
  ver == '3.8.2S' ||
  ver == '3.8.5E' ||
  ver == '3.9.0S' ||
  ver == '3.9.1S' ||
  ver == '3.9.2S'
) flag++;

# Check that device is configured with SNMP support
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_mib", "show snmp mib");
  if (check_cisco_result(buf))
  {
    # "Not all of the MIBs will be displayed in the output of the show
    # snmp mib command but may still be enabled. Customers are advised
    # to implement the entire exclude list as detailed in the
    # Workarounds section of the advisory.""
    if (preg(multiline:TRUE, pattern:"(ADSL-LINE|ALPS|CISCO-ADSL-DMT-LINE|CISCO-BSTUN|CISCO-MAC-AUTH-BYPASS|CISCO-SLB-EXT|CISCO-VOICE-DNIS|CISCO-VOICE-NUMBER-EXPANSION|TN3270E-RT)-MIB", string:buf))
    {
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCve54313, CSCve57697, CSCve60276, CSCve60376, CSCve60402, CSCve60507, CSCve66540, CSCve66601, CSCve66658, CSCve78027, CSCve89865",
    cmds     : make_list("show snmp mib")
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
