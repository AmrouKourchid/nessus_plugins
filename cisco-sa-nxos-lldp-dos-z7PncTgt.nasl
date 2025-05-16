#TRUSTED 76611258968c8a5644228b992e8fe344550c554911cd93742912a28bb4b19751e3ca24fcf1851ec6f210cbd589c86bc9d4cab0146c19303eade6df935021b0cae6dd6b0fd835a6c37d76bf1a09738520338d27328092cc7a432e1eb230e4f850f360617a06a956e54259b62c5c1485ea9cf1bff3cdc46d53c426968afb9dcc9418f07da28b37b867e13562f7c776502d7249a804792f48307053a34d30b8a89d1a5c5b3a3d58cc266ceaa86bd3fd1584d7e98a579c8f79edfe745c4b24ce9a77e5235b04c556d53cad4fa3ca3c6ed99040b611577415c2786a5996b1ecb0b489df690d9d71497c5a4af0c2171feb38f66b2ad4f2250aab890d4f9f2d2d49fd61f72b2fcaf67d8145774ddb87ef825b906095a57aec2a5361da2c3e145fea10ede9024a3ee0230d713690b55812e431968ecdea886bd9b1eb56a798de0d80a5a163124552695c7e773a787a8e002fffc01599f5d942ce261388e6f0c749fb123df2e56401eafa8da6ce511eca8803d37273e3360cfa574127ecdae942c98014fb41ce3faf7752f91581f731c9e077bc2796159673f2c999c730393ff0cf878ba8d6a0e981e5df589fed2c91c2e46c3646a7e470120b7fb362671009ff5621432a08fb43425a644bde1387df7c845e06cbb92f412f67363562cf00c73fc26a3565cde4407d0a7c63f8e40bb58b0e0d2ad3071d964c0b617be01f2b725c6015bc4c
#TRUST-RSA-SHA256 0a59e6bf85d7b408b554a64280e7e8aa5beebc4630f0866ee1c2e9fa1392b111a92c9d8186698941fb8b185c52a80b659d9183188a88376e238d5ac2806899a1f637b2a0f2b48be40de58005ad727b993639078c84aaab54503a1d7fd89f573c3f3f6d663307b00ce034c2233dc8e0663660d8e5a06d147d0d448a5b584b5400d55f02126ca9d39fda5b71a929beee264db0a15b3437e061f94d1eefaa6f2480fa589f86737f0f0ec60b342566f2e8ddce9bc2c02130a77ceaae482cf978e7ddad8b463bc8099c0ca72e0f37f09caa330bd42167e5ec282e57a6dd6725ec1202404cdff78c364e3175f7423f1051ff25cf47831684c23c84f39372b4607540bc3e0ffa9874adf3e5c2ceb175fcb137e527e0ba256ce5c71126c63f639611e99fcc3b2d98f747f2588f64b70672bd1cffdf56d141d3f8263a631f0c6b7f474e678f96da4460a10f8808955c06cd2780b5cfb2150bcf24c0283e56592e5b350222206b775895210447dfb419de7c96f61e046f93542c20d4674aeefa272604439381f627bad96f526b77696f90fab3b602f0045033fb30d37c38202a4f9abc49d8ee03e7c4ee59556c60fe6cce0a956fb6a6da81d378e809cfbf0eafed0c137d30637122ea4121690056ced1537f462a297804fcbbcee5933a01b23b3096e24af5a8b41e158da4f2d17d7ec8e475b69b52d070055e83de9039cd3c9558b0ee1cdc
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191647);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2024-20294");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe86457");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67409");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67411");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf67468");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi29934");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi31871");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-lldp-dos-z7PncTgt");
  script_xref(name:"IAVA", value:"2024-A-0129");

  script_name(english:"Cisco NX-OS Software Link Layer Discovery Protocol DoS (cisco-sa-nxos-lldp-dos-z7PncTgt)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS System Software is affected by a denial of service (DoS)
vulnerability. The vulnerability lies in the Link Layer Discovery Protocol (LLDP) feature of Cisco NX-OS Software and
could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on an affected device.
This vulnerability is due to improper handling of specific fields in an LLDP frame. An attacker could exploit this 
vulnerability by sending a crafted LLDP packet to an interface of an affected device and having an authenticated user 
retrieve LLDP statistics from the affected device through CLI show commands or Simple Network Management Protocol (SNMP)
requests. A successful exploit could allow the attacker to cause the LLDP service to crash and stop running on the
affected device. In certain situations, the LLDP crash may result in a reload of the affected device. Note: LLDP is a
Layer 2 link protocol. To exploit this vulnerability, an attacker would need to be directly connected to an interface
of an affected device, either physically or logically (for example, through a Layer 2 Tunnel configured to transport the
LLDP protocol).

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-lldp-dos-z7PncTgt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?789ffa5c");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e327a04a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe86457");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67409");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67411");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67412");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf67468");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi29934");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi31871");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe86457, CSCwf67408, CSCwf67409, CSCwf67411,
CSCwf67412, CSCwf67468, CSCwi29934, CSCwi31871");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(805);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

# out of the affected device list, MDS, Nexus and UCS run NX-OS
if (('MDS' >!< product_info.device || product_info.model !~ "^9[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])5[5-6][0-9]{1,2}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])6[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])7[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}") &&
    ('UCS' >!< product_info.device || product_info.model !~ "(^|[^0-9])6[2-5][0-9]{1,2}"))
audit(AUDIT_HOST_NOT, 'affected');

var version_list = [];
var vuln_ranges = [];
var lldp_default = 0;

if ('MDS' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(1)',
    '6.2(3)',
    '6.2(5)',
    '6.2(5a)',
    '6.2(5b)',
    '6.2(7)',
    '6.2(9)',
    '6.2(9a)',
    '6.2(9b)',
    '6.2(9c)',
    '6.2(11)',
    '6.2(11b)',
    '6.2(11c)',
    '6.2(11d)',
    '6.2(11e)',
    '6.2(13)',
    '6.2(13a)',
    '6.2(13b)',
    '6.2(15)',
    '6.2(17)',
    '6.2(19)',
    '6.2(21)',
    '6.2(23)',
    '6.2(25)',
    '6.2(17a)',
    '6.2(27)',
    '6.2(29)',
    '6.2(31)',
    '6.2(33)',
    '7.3(0)D1(1)',
    '7.3(0)DY(1)',
    '7.3(1)D1(1)',
    '7.3(1)DY(1)',
    '8.1(1)',
    '8.1(1a)',
    '8.1(1b)',
    '8.2(1)',
    '8.2(2)',
    '8.3(1)',
    '8.3(2)',
    '9.2(1)',
    '9.2(2)',
    '9.2(1a)',
    '8.4(1)',
    '8.4(1a)',
    '8.4(2)',
    '8.4(2a)',
    '8.4(2b)',
    '8.4(2c)',
    '8.4(2d)',
    '8.4(2e)',
    '8.4(2f)',
    '9.3(1)',
    '9.3(2)',
    '9.3(2a)',
    '8.5(1)'
    );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
    '6.0(2)A3(1)',
    '6.0(2)A3(2)',
    '6.0(2)A3(4)',
    '6.0(2)A4(1)',
    '6.0(2)A4(2)',
    '6.0(2)A4(3)',
    '6.0(2)A4(4)',
    '6.0(2)A4(5)',
    '6.0(2)A4(6)',
    '6.0(2)A6(1)',
    '6.0(2)A6(1a)',
    '6.0(2)A6(2)',
    '6.0(2)A6(2a)',
    '6.0(2)A6(3)',
    '6.0(2)A6(3a)',
    '6.0(2)A6(4)',
    '6.0(2)A6(4a)',
    '6.0(2)A6(5)',
    '6.0(2)A6(5a)',
    '6.0(2)A6(5b)',
    '6.0(2)A6(6)',
    '6.0(2)A6(7)',
    '6.0(2)A6(8)',
    '6.0(2)A7(1)',
    '6.0(2)A7(1a)',
    '6.0(2)A7(2)',
    '6.0(2)A7(2a)',
    '6.0(2)A8(1)',
    '6.0(2)A8(2)',
    '6.0(2)A8(3)',
    '6.0(2)A8(4)',
    '6.0(2)A8(4a)',
    '6.0(2)A8(5)',
    '6.0(2)A8(6)',
    '6.0(2)A8(7)',
    '6.0(2)A8(7a)',
    '6.0(2)A8(7b)',
    '6.0(2)A8(8)',
    '6.0(2)A8(9)',
    '6.0(2)A8(10a)',
    '6.0(2)A8(10)',
    '6.0(2)A8(11)',
    '6.0(2)A8(11a)',
    '6.0(2)A8(11b)',
    '6.0(2)U2(1)',
    '6.0(2)U2(2)',
    '6.0(2)U2(3)',
    '6.0(2)U2(4)',
    '6.0(2)U2(5)',
    '6.0(2)U2(6)',
    '6.0(2)U3(1)',
    '6.0(2)U3(2)',
    '6.0(2)U3(3)',
    '6.0(2)U3(4)',
    '6.0(2)U3(5)',
    '6.0(2)U3(6)',
    '6.0(2)U3(7)',
    '6.0(2)U3(8)',
    '6.0(2)U3(9)',
    '6.0(2)U4(1)',
    '6.0(2)U4(2)',
    '6.0(2)U4(3)',
    '6.0(2)U4(4)',
    '6.0(2)U5(1)',
    '6.0(2)U5(2)',
    '6.0(2)U5(3)',
    '6.0(2)U5(4)',
    '6.0(2)U6(1)',
    '6.0(2)U6(2)',
    '6.0(2)U6(3)',
    '6.0(2)U6(4)',
    '6.0(2)U6(5)',
    '6.0(2)U6(6)',
    '6.0(2)U6(7)',
    '6.0(2)U6(8)',
    '6.0(2)U6(1a)',
    '6.0(2)U6(2a)',
    '6.0(2)U6(3a)',
    '6.0(2)U6(4a)',
    '6.0(2)U6(5a)',
    '6.0(2)U6(5b)',
    '6.0(2)U6(5c)',
    '6.0(2)U6(9)',
    '6.0(2)U6(10)',
    '6.0(2)U6(10a)',
    '7.0(3)F3(1)',
    '7.0(3)F3(2)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I2(2a)',
    '7.0(3)I2(2b)',
    '7.0(3)I2(2c)',
    '7.0(3)I2(2d)',
    '7.0(3)I2(2e)',
    '7.0(3)I2(3)',
    '7.0(3)I2(4)',
    '7.0(3)I2(5)',
    '7.0(3)I2(1)',
    '7.0(3)I2(1a)',
    '7.0(3)I2(2)',
    '7.0(3)I2(2r)',
    '7.0(3)I2(2s)',
    '7.0(3)I2(2v)',
    '7.0(3)I2(2w)',
    '7.0(3)I2(2x)',
    '7.0(3)I2(2y)',
    '7.0(3)I3(1)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(6z)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
    '7.0(3)IC4(4)',
    '7.0(3)IM7(2)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '10.1(1)',
    '10.1(2)',
    '10.1(2t)',
    '10.2(1)',
    '10.2(2)',
    '10.2(3)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.2(3v)',
    '10.3(1)',
    '10.3(2)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^5[5-6][0-9]{1,2}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)',
    '7.3(13)N1(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^6[0-9]{2,3}")
{
  version_list = make_list(
    '7.1(0)N1(1a)',
    '7.1(0)N1(1b)',
    '7.1(0)N1(1)',
    '7.1(1)N1(1)',
    '7.1(1)N1(1a)',
    '7.1(2)N1(1)',
    '7.1(2)N1(1a)',
    '7.1(3)N1(1)',
    '7.1(3)N1(2)',
    '7.1(3)N1(5)',
    '7.1(3)N1(4)',
    '7.1(3)N1(3)',
    '7.1(3)N1(2a)',
    '7.1(4)N1(1)',
    '7.1(4)N1(1d)',
    '7.1(4)N1(1c)',
    '7.1(4)N1(1a)',
    '7.1(5)N1(1)',
    '7.1(5)N1(1b)',
    '7.3(0)N1(1)',
    '7.3(0)N1(1b)',
    '7.3(0)N1(1a)',
    '7.3(1)N1(1)',
    '7.3(2)N1(1)',
    '7.3(2)N1(1b)',
    '7.3(2)N1(1c)',
    '7.3(3)N1(1)',
    '7.3(4)N1(1)',
    '7.3(4)N1(1a)',
    '7.3(5)N1(1)',
    '7.3(6)N1(1)',
    '7.3(6)N1(1a)',
    '7.3(7)N1(1)',
    '7.3(7)N1(1a)',
    '7.3(7)N1(1b)',
    '7.3(8)N1(1)',
    '7.3(8)N1(1a)',
    '7.3(8)N1(1b)',
    '7.3(9)N1(1)',
    '7.3(10)N1(1)',
    '7.3(11)N1(1)',
    '7.3(11)N1(1a)',
    '7.3(12)N1(1)',
    '7.3(13)N1(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^7[0-9]{2,3}")
{
  version_list = make_list(
    '6.2(2)',
    '6.2(2a)',
    '6.2(6)',
    '6.2(6b)',
    '6.2(8)',
    '6.2(8a)',
    '6.2(8b)',
    '6.2(10)',
    '6.2(12)',
    '6.2(18)',
    '6.2(16)',
    '6.2(14b)',
    '6.2(14)',
    '6.2(14a)',
    '6.2(6a)',
    '6.2(20)',
    '6.2(20a)',
    '6.2(22)',
    '6.2(24)',
    '6.2(24a)',
    '6.2(26)',
    '7.2(0)D1(1)',
    '7.2(1)D1(1)',
    '7.2(2)D1(2)',
    '7.2(2)D1(1)',
    '7.2(2)D1(3)',
    '7.2(2)D1(4)',
    '7.3(0)D1(1)',
    '7.3(0)DX(1)',
    '7.3(1)D1(1)',
    '7.3(2)D1(1)',
    '7.3(2)D1(2)',
    '7.3(2)D1(3)',
    '7.3(2)D1(3a)',
    '7.3(2)D1(1d)',
    '8.0(1)',
    '8.1(1)',
    '8.1(2)',
    '8.1(2a)',
    '8.2(1)',
    '8.2(2)',
    '8.2(3)',
    '8.2(4)',
    '8.2(5)',
    '8.2(6)',
    '8.2(7)',
    '8.2(7a)',
    '8.2(8)',
    '8.2(9)',
    '8.2(10)',
    '8.3(1)',
    '8.3(2)',
    '7.3(3)D1(1)',
    '7.3(4)D1(1)',
    '8.4(1)',
    '8.4(2)',
    '8.4(3)',
    '8.4(4)',
    '8.4(4a)',
    '8.4(5)',
    '8.4(6)',
    '8.4(6a)',
    '8.4(7)',
    '7.3(5)D1(1)',
    '7.3(6)D1(1)',
    '7.3(7)D1(1)',
    '7.3(8)D1(1)',
    '7.3(9)D1(1)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  # if Nexus 9k in ACI mode, LLDP is on by default and it cannot be disabled
  if (!empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
    lldp_default = 1;
  
  version_list = make_list(
    '7.0(3)F1(1)',
    '7.0(3)F2(1)',
    '7.0(3)F2(2)',
    '7.0(3)F3(1)',
    '7.0(3)F3(3)',
    '7.0(3)F3(3a)',
    '7.0(3)F3(4)',
    '7.0(3)F3(3c)',
    '7.0(3)F3(5)',
    '7.0(3)I2(2a)',
    '7.0(3)I2(2b)',
    '7.0(3)I2(2c)',
    '7.0(3)I2(2d)',
    '7.0(3)I2(2e)',
    '7.0(3)I2(3)',
    '7.0(3)I2(4)',
    '7.0(3)I2(5)',
    '7.0(3)I2(1)',
    '7.0(3)I2(1a)',
    '7.0(3)I2(2)',
    '7.0(3)I2(2r)',
    '7.0(3)I2(2s)',
    '7.0(3)I2(2v)',
    '7.0(3)I2(2w)',
    '7.0(3)I2(2x)',
    '7.0(3)I2(2y)',
    '7.0(3)I3(1)',
    '7.0(3)I4(1)',
    '7.0(3)I4(2)',
    '7.0(3)I4(3)',
    '7.0(3)I4(4)',
    '7.0(3)I4(5)',
    '7.0(3)I4(6)',
    '7.0(3)I4(7)',
    '7.0(3)I4(8)',
    '7.0(3)I4(8a)',
    '7.0(3)I4(8b)',
    '7.0(3)I4(8z)',
    '7.0(3)I4(1t)',
    '7.0(3)I4(6t)',
    '7.0(3)I4(9)',
    '7.0(3)I5(1)',
    '7.0(3)I5(2)',
    '7.0(3)I5(3)',
    '7.0(3)I5(3a)',
    '7.0(3)I5(3b)',
    '7.0(3)I6(1)',
    '7.0(3)I6(2)',
    '7.0(3)I7(1)',
    '7.0(3)I7(2)',
    '7.0(3)I7(3)',
    '7.0(3)I7(4)',
    '7.0(3)I7(5)',
    '7.0(3)I7(5a)',
    '7.0(3)I7(3z)',
    '7.0(3)I7(6)',
    '7.0(3)I7(7)',
    '7.0(3)I7(8)',
    '7.0(3)I7(9)',
    '7.0(3)I7(9w)',
    '7.0(3)I7(10)',
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '7.0(3)IA7(1)',
    '7.0(3)IA7(2)',
    '7.0(3)IC4(4)',
    '7.0(3)IM3(1)',
    '7.0(3)IM3(2)',
    '7.0(3)IM3(2a)',
    '7.0(3)IM3(2b)',
    '7.0(3)IM3(3)',
    '9.3(1)',
    '9.3(2)',
    '9.3(3)',
    '9.3(1z)',
    '9.3(4)',
    '9.3(5)',
    '9.3(6)',
    '9.3(5w)',
    '9.3(7)',
    '9.3(7k)',
    '9.3(7a)',
    '9.3(8)',
    '9.3(9)',
    '9.3(10)',
    '9.3(11)',
    '10.1(1)',
    '10.1(2)',
    '10.2(1)',
    '10.2(1q)',
    '10.2(2)',
    '10.2(3)',
    '10.2(2a)',
    '10.2(3t)',
    '10.2(4)',
    '10.2(5)',
    '10.3(1)',
    '10.3(2)',
    '12.0(1m)',
    '12.0(2g)',
    '12.0(1n)',
    '12.0(1o)',
    '12.0(1p)',
    '12.0(1q)',
    '12.0(2h)',
    '12.0(2l)',
    '12.0(2m)',
    '12.0(2n)',
    '12.0(2o)',
    '12.0(2f)',
    '12.0(1r)',
    '12.1(1h)',
    '12.1(2e)',
    '12.1(3g)',
    '12.1(4a)',
    '12.1(1i)',
    '12.1(2g)',
    '12.1(2k)',
    '12.1(3h)',
    '12.1(3j)',
    '12.2(1n)',
    '12.2(2e)',
    '12.2(3j)',
    '12.2(4f)',
    '12.2(4p)',
    '12.2(3p)',
    '12.2(3r)',
    '12.2(3s)',
    '12.2(3t)',
    '12.2(2f)',
    '12.2(2i)',
    '12.2(2j)',
    '12.2(2k)',
    '12.2(2q)',
    '12.2(1o)',
    '12.2(4q)',
    '12.2(4r)',
    '12.2(1k)',
    '12.3(1e)',
    '12.3(1f)',
    '12.3(1i)',
    '12.3(1l)',
    '12.3(1o)',
    '12.3(1p)',
    '13.0(1k)',
    '13.0(2h)',
    '13.0(2k)',
    '13.0(2n)',
    '13.1(1i)',
    '13.1(2m)',
    '13.1(2o)',
    '13.1(2p)',
    '13.1(2q)',
    '13.1(2s)',
    '13.1(2t)',
    '13.1(2u)',
    '13.1(2v)',
    '13.2(1l)',
    '13.2(1m)',
    '13.2(2l)',
    '13.2(2o)',
    '13.2(3i)',
    '13.2(3n)',
    '13.2(3o)',
    '13.2(3r)',
    '13.2(4d)',
    '13.2(4e)',
    '13.2(3j)',
    '13.2(3s)',
    '13.2(5d)',
    '13.2(5e)',
    '13.2(5f)',
    '13.2(6i)',
    '13.2(41d)',
    '13.2(7f)',
    '13.2(7k)',
    '13.2(9b)',
    '13.2(8d)',
    '13.2(9f)',
    '13.2(9h)',
    '13.2(10e)',
    '13.2(10f)',
    '13.2(10g)',
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
    '15.2(8d)',
    '15.2(8e)',
    '15.2(8f)',
    '15.2(8g)',
    '16.0(1g)',
    '16.0(1j)',
    '16.0(2h)',
    '16.0(2j)',
    '16.0(3d)',
    '16.0(3e)',
    '15.3(1d)'
  );
}
  
if ('UCS' >< product_info.device && product_info.model =~ "^6[2-5][0-9]{1,2}")
{
  # if UCS in ACI mode, LLDP is on by default and it cannot be disabled
  if (!empty_or_null(get_kb_item("Host/aci/system/chassis/summary")))
    lldp_default = 1;

  vuln_ranges = [
    {'min_ver' : '0.0', 'fix_ver' : '4.1(3m)'},
    {'min_ver' : '4.2', 'fix_ver' : '4.2(3)'},
    {'min_ver' : '4.3', 'fix_ver' : '4.3(2b)'}
  ];
}
  
var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe86457, CSCwf67408, CSCwf67409, CSCwf67411, CSCwf67412, CSCwf67468, CSCwi29934, CSCwi31871'
);
    
var workarounds = NULL;
var workaround_params = NULL;
# if N9k or UCS in ACI, no workaround checks needed
if (!lldp_default)
{
  reporting['cmds'] = make_list('show feature');
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [WORKAROUND_CONFIG['nxos_lldp_enabled']];
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
