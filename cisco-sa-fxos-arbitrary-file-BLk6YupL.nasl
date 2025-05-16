#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216908);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2023-20234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwb91812");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd05772");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd35722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd35726");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxos-arbitrary-file-BLk6YupL");

  script_name(english:"Cisco FXOS Software Arbitrary File Write (cisco-sa-fxos-arbitrary-file-BLk6YupL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS is affected by a vulnerability. The vulnerability lies in the Link
Layer Discovery Protocol (LLDP) feature of Cisco FXOS Software and could allow an unauthenticated, adjacent attacker to
cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper handling of
specific fields in an LLDP frame. An attacker could exploit this vulnerability by sending a crafted LLDP packet to an
interface of an affected device and having an authenticated user retrieve LLDP statistics from the affected device 
through CLI show commands or Simple Network Management Protocol (SNMP) requests. A successful exploit could allow the
attacker to cause the LLDP service to crash and stop running on the affected device. In certain situations, the LLDP
crash may result in a reload of the affected device. Note: LLDP is a Layer 2 link protocol. To exploit this 
vulnerability, an attacker would need to be directly connected to an interface of an affected device, either physically 
or logically (for example, through a Layer 2 Tunnel configured to transport the LLDP protocol).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxos-arbitrary-file-BLk6YupL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?283ad651");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwb91812, CSCwd05772, CSCwd35722, CSCwd35726");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20234");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'FXOS');

if (product_info['model'] !~ "1[0-9-]{3}|[234]1[0-9]{2}|93[0-9]{2}") 
  audit(AUDIT_HOST_NOT, 'affected');

var version_list = [
  '2.2.1.63',
  '2.2.1.66',
  '2.2.1.70',
  '2.2.2.17',
  '2.2.2.19',
  '2.2.2.24',
  '2.2.2.26',
  '2.2.2.28',
  '2.2.2.54',
  '2.2.2.60',
  '2.2.2.71',
  '2.2.2.83',
  '2.2.2.86',
  '2.2.2.91',
  '2.2.2.97',
  '2.2.2.101',
  '2.2.2.137',
  '2.2.2.148',
  '2.2.2.149',
  '2.3.1.99',
  '2.3.1.93',
  '2.3.1.91',
  '2.3.1.88',
  '2.3.1.75',
  '2.3.1.73',
  '2.3.1.66',
  '2.3.1.58',
  '2.3.1.130',
  '2.3.1.111',
  '2.3.1.110',
  '2.3.1.144',
  '2.3.1.145',
  '2.3.1.155',
  '2.3.1.166',
  '2.3.1.173',
  '2.3.1.179',
  '2.3.1.180',
  '2.3.1.56',
  '2.3.1.190',
  '2.3.1.215',
  '2.3.1.216',
  '2.3.1.219',
  '2.3.1.230',
  '2.6.1.131',
  '2.6.1.157',
  '2.6.1.166',
  '2.6.1.169',
  '2.6.1.174',
  '2.6.1.187',
  '2.6.1.192',
  '2.6.1.204',
  '2.6.1.214',
  '2.6.1.224',
  '2.6.1.229',
  '2.6.1.230',
  '2.6.1.238',
  '2.6.1.239',
  '2.6.1.254',
  '2.6.1.259',
  '2.8.1.105',
  '2.8.1.125',
  '2.8.1.139',
  '2.8.1.143',
  '2.8.1.152',
  '2.8.1.162',
  '2.8.1.164',
  '2.8.1.172',
  '2.8.1.186',
  '2.8.1.190',
  '2.10.1.159',
  '2.10.1.166',
  '2.10.1.179',
  '2.10.1.207',
  '2.10.1.234',
  '2.11.1.154',
  '2.11.1.182',
  '2.12.0.31',
  '2.12.0.432',
  '2.12.0.450',
  '2.13.0.198'
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwb91812, CSCwd05772, CSCwd35722, CSCwd35726'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
