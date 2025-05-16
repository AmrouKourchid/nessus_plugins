#TRUSTED 99b2c9e8608491bc41df60aaac274435b8590846151735f271815331f97004e93d4d3ae35d8d3e78aa8f06181b96f496d7b1a09084daf0af253efc3a25b9c1ab7d6bc1c0d351f45e8061257154d2cace48a99bc5cf0e8ad34021720b8289137ac9653343bbe49aa1deaa964026b395d4d5b79f9d6bd80811ed55e79bfe686f84213458b61e4a1a82791edce4179cd84317d3963811ba50fdf5b7467880fb9e69a3ee2919baf64f7b97820fc9d620bb866a12e69bd33297e85b92eae4eb9636a2c6c84e9aa554aa91ecb6074e3903dea614ef1e2f442b5684395982d85fe1b6f973ff27058a3da85b6d4ae8f8921bd1fecc4bd67c6288ae90074f5b8c7d2b8e514e974bdb686a137ef5483ff1148e98ff32154bb88f5caa1d42f62965d37541d1d4262e2fb0a59df55a28b4fb02fa00a4c390866a2a2d6e5ebc214a55c6af5d7833ff215e47391d28be0835a163ffcaf7ee934ed4dd826a26611476b9959a63aed5f2838335a9ea6f7bd53784e9f604bfde8bf397e361ad43dcc3b448108196df2f342b932ed44f4e82b8fe8ef7da010743ef31000b4964a6be78cdddb2dfb777aadd193458455df50d71ea29a120e7794a0fd89d8323a85352ff005c7373d849d340ae03908af6b69da53d101654eb59853beb6b4085a24fb12fb086091102a153c95ad4096b367be5ecfe217192e5d03dd85d5cda23ee7386a29dbb24e6933b
#TRUST-RSA-SHA256 32066e2fac39f7538fc29a45d2a802edf4f99b064e869939b0256e42b17ca9b99b5360e389ef583a75adc821361e906239dd8c42c437c4f9844275593b97078285055dd891b0d5f9dd50b5d6164635b8a3aed434b97ffa0afe0eb115fea991b556c6a27ae8dcfc460a96200210e12d0c88b2b195940354029002feb327f2d9f07d490cb1d62e6ecf5e366b6b9e8ffb826efe394cf143687eb5ff2c9693fb28f544798b4cffb8b670669bd82069936a3547fa53750a45b4635bf50f5dee314bea8a640e08f5b97c3381455e74ba891cb74fef8be7dd5a807250b0f8176b0275f9e7a341cdbdcae71e0c10805a8a4c2fe48a4007559230020a13a62075916b410a2103a47a57c3105b80ac18610cd7b7c71b9928645e5357e98c1887b9be5419ed0aaa9e36643182ae05a90316c84a99dc44c3d8a5f511fb8218ee727dda9eaa53981db9966fb9a75e8dbe756b980e216f11b3ed1f68db6dbd5da4f4cb135d3d5eac53202f9f8a9976bb16f6c562c31b8ea4c30ca98e748847d7e6b477f382a18592205fee21afc9e931230b319957d8d8b112183d60fc26bcae35427994dfb56ed1b4d0f009717f97bf8c22d47293ab58ee5c379bfa3a14b55b1dc3ea0ed3ed35b9b58c1edacff23bb8a553f351b675b8775898b204cd08e4881535a98896bfb1d171e4d8fb11066c4c2b23aeaf06a824cc3df21c8c89cf3cd84b23b5cf399d77
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181009);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-20200");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi80806");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO");

  script_name(english:"Cisco Firepower 4100 Series, Firepower 9300 Security Appliances SNMP DoS (cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Simple Network Management Protocol (SNMP) service of Cisco FXOS Software for Firepower 4100 
Series and Firepower 9300 Security Appliances could allow an authenticated, remote attacker to cause a denial of 
service (DoS) condition on an affected device. This vulnerability is due to the improper handling of specific SNMP 
requests. An attacker could exploit this vulnerability by sending a crafted SNMP request to an affected device. 
A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition. 
Note: This vulnerability affects all supported SNMP versions. To exploit this vulnerability through SNMPv2c or earlier, 
an attacker must know the SNMP community string that is configured on an affected device. To exploit this vulnerability 
through SNMPv3, the attacker must have valid credentials for an SNMP user who is configured on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae8f9985");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1feb9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi80806");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi80806");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20200");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'FXOS');

# Vulnerable model list Cisco Firepower 4100 Series / 9300 Security Appliances
if (product_info['model'] !~ "(41[0-9]{2}|9[0-3][0-9]{2})") 
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = [
    '2.0(1.68)',
    '2.0(1.201)',
    '2.0(1.86)',
    '2.0(1.37)',
    '2.0(1.135)',
    '2.0(1.141)',
    '2.0(1.144)',
    '2.0(1.148)',
    '2.0(1.149)',
    '2.0(1.153)',
    '2.0(1.159)',
    '2.0(1.188)',
    '2.0(1.203)',
    '2.0(1.204)',
    '2.0(1.206)',
    '2.1(1.64)',
    '2.1(1.73)',
    '2.1(1.77)',
    '2.1(1.83)',
    '2.1(1.85)',
    '2.1(1.86)',
    '2.1(1.97)',
    '2.1(1.106)',
    '2.1(1.107)',
    '2.1(1.113)',
    '2.1(1.115)',
    '2.1(1.116)',
    '2.2(1.63)',
    '2.2(1.66)',
    '2.2(1.70)',
    '2.2(2.17)',
    '2.2(2.19)',
    '2.2(2.24)',
    '2.2(2.26)',
    '2.2(2.28)',
    '2.2(2.54)',
    '2.2(2.60)',
    '2.3(1.93)',
    '2.3(1.91)',
    '2.3(1.88)',
    '2.3(1.75)',
    '2.3(1.73)',
    '2.3(1.66)',
    '2.3(1.58)',
    '2.3(1.56)'
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvi80806',
  'cmds'          , make_list('show running-config') 
);

var workarounds = make_list(CISCO_WORKAROUNDS['snmp_admin']);
var workaround_params = make_list();

cisco::check_and_report(
  workarounds       : workarounds,
  workaround_params : workaround_params,
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
