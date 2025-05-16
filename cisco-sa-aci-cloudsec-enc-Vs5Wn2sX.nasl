#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178417);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/19");

  script_cve_id("CVE-2023-20185");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf02544");
  script_xref(name:"CISCO-SA", value:"cisco-sa-aci-cloudsec-enc-Vs5Wn2sX");

  script_name(english:"Cisco ACI Multi-Site CloudSec Encryption Information Disclosure (cisco-sa-aci-cloudsec-enc-Vs5Wn2sX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software in ACI Mode is affected by an information
disclosure vulnerability. The vulnerability affects Cisco Nexus 9000 Series Fabric Switches in Application Centric
Infrastructure (ACI) mode of Multi-Site that are part of a Multi-Site topology and have the CloudSec encryption
feature enabled. Due to an issue with the implementation of the ciphers that are used by the CloudSec encryption feature
, an unauthenticated, remote attacker with an on-path position between the ACI sites could exploit this vulnerability by
intercepting intersite encrypted traffic and using cryptanalytic techniques to break the encryption. Successful 
exploitation could allow the attacker to read or modify the traffic that is transmitted between the sites.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-cloudsec-enc-Vs5Wn2sX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54db6797");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf02544");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf02544");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20185");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device", "Host/aci/system/chassis/summary");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

# Nexus 9k
if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
  audit(AUDIT_HOST_NOT, 'an affected model');

# ACI mode
if (empty_or_null(get_kb_list('Host/aci/*')))
  audit(AUDIT_HOST_NOT, 'an affected model due to non ACI mode');

# Not checking for Multi-Site + CloudSec config
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Cisco NX-OS');

var version_list = make_list(
  '14.0(1h)',
  '14.0(2c)',
  '14.0(3d)',
  '14.0(3c)',
  '14.1(1i)',
  '14.1(1j)',
  '14.1(1k)',
  '14.1(1l)',
  '14.1(2g)',
  '14.1(2m)',
  '14.1(2o)',
  '14.1(2s)',
  '14.1(2u)',
  '14.1(2w)',
  '14.1(2x)',
  '14.2(1i)',
  '14.2(1j)',
  '14.2(1l)',
  '14.2(2e)',
  '14.2(2f)',
  '14.2(2g)',
  '14.2(3j)',
  '14.2(3l)',
  '14.2(3n)',
  '14.2(3q)',
  '14.2(4i)',
  '14.2(4k)',
  '14.2(4o)',
  '14.2(4p)',
  '14.2(5k)',
  '14.2(5l)',
  '14.2(5n)',
  '14.2(6d)',
  '14.2(6g)',
  '14.2(6h)',
  '14.2(6l)',
  '14.2(7f)',
  '14.2(7l)',
  '14.2(6o)',
  '14.2(7q)',
  '14.2(7r)',
  '14.2(7s)',
  '14.2(7t)',
  '14.2(7u)',
  '14.2(7v)',
  '14.2(7w)',
  '15.0(1k)',
  '15.0(1l)',
  '15.0(2e)',
  '15.0(2h)',
  '15.1(1h)',
  '15.1(2e)',
  '15.1(3e)',
  '15.1(4c)',
  '15.2(1g)',
  '15.2(2e)',
  '15.2(2f)',
  '15.2(2g)',
  '15.2(2h)',
  '15.2(3e)',
  '15.2(3f)',
  '15.2(3g)',
  '15.2(4d)',
  '15.2(4e)',
  '15.2(5c)',
  '15.2(5d)',
  '15.2(5e)',
  '15.2(4f)',
  '15.2(6e)',
  '15.2(6g)',
  '15.2(7f)',
  '15.2(7g)',
  '15.2(6h)',
  '16.0(1g)',
  '16.0(1j)',
  '16.0(2h)'
);

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf02544'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
