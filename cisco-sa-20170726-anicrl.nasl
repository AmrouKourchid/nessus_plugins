#TRUSTED 9395ddbdc2bf3a2703480b8b764da6fc885372726280a1a7b7ee25b8e991eb084853588e2b542b638ada6544ecb859aa8a014725cefdb545b7c7e49122194e34a668a466a4df699576fc94ad1550bf6505f180e6374a07c98bf9db6f578d29c7725013ceee80272c6a24fc9793bb2ab0db097e0afb3a83e4b748cec45081f5a790cb7f66b73b7bc1c088a7f462e39c0f7f80d0c2686e0f3a2269ebb24e3e081a33c437150a913c46044b8dcf98a11dfc333b0bad2434c93259c48bc9db4566a43b48081347e8da5c2bd5c3afed11770d8100d6da8bde9cf1db37a93a484e7a82766c6feeb829fba169b02c7ef87c9024cf3ef6df71fe199bade855e9634b7c3496e9c10ad4b8dbecfef89a9743b677d34ecde403f0d01eec19edebbf135cd5075d7a2a328fffa8b2acbd7841a84dc9cf9ac9e91b25953ff5cd176034e36685f977466cdc32c857f61fce5c8061ff1c0757d88966d41c07dd4994671bacf2fe8237677d650dad9925a8fef1a66bdbd46b356c5d9563ab7e3c8aae4d8971a70b5abfbba25500de1e4184eadc2021b2909538abde779e58cedf2fb2965d6d69e708a299f84834932a196c278d12a5f5b725649c58c6b76cd2c819cc0017a73d3791aab6bbcd2aa6f5784d8e402c69f6dbd084d23abf93ac21276930a6f38e875be8086a2d00c960a03b77f143784eab03b43d7e6f10f1ecf3c769a789648520eab4
#TRUST-RSA-SHA256 11b40d74c7e25ef7723e8a08ab0b8c6f013bbd1b63f56f8b083a6d7f5eb8d62fa93799e597f093bbe90e88d3c11396fb2095864d3d92a950b0908cb778230d9fe798f6d261e2f647e9461fcc5a5f448b86f0bbf13276bd11de1b1c817079896fd7a50642f0dba607d625e4c1d5ac7ff61ba64b16134c02db2f59fe3ae7a3b62b2fb0dcf212af2565f580a293fc97ff67f4155118227df42bbf1f746fb3db4df9b90d73db82e78948a9d56fdd4d6677e912d0870d137f7e8e4e8e9a39ad15275aef00284b08c1fc6cc15c286fb9b5fcda6791ab05eab34f4d55ceb59c798e6fad73585da8df16a0de06566126d1d9d224e969889ece91419df8471685258f7e4233bd01f35e3b3fd47f47cf3a5eea0f7c88e159f3827661d7a3ebb13ca79c91f8b96bc67333b38b01ea32ec8ea8333122214ec21b3cdd79722f2a0c70e6ce3e5debb6b0faee439b64492e862c572f47b61e1522250e66e7fddb2d1680bf82c4af90c9e1fa84645964a329a842746aed6e78e3498b40a8a85197718e13209381dc071ed0f3711f042ff5a2eaf0909a0984886aa104e05a004d81fde685fe62f4b2794f1c02a93705a33b51f9049790a337c24ff534605fa196d954f5889125841609bace32ad7af89f6774f188dc3d0f7caaa47581ee6db1b8b518215d6c7cf800af4550796990a8ca361ed2abb3f5e580ff7262d9c6eb746a211563463c7bae38
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131131);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2017-6664");
  script_bugtraq_id(99986);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd22328");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170726-anicrl");

  script_name(english:"Cisco IOS XE Software Autonomic Networking Infrastructure Certificate Revocation (cisco-sa-20170726-anicrl)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability in the Autonomic
Networking feature because the affected software does not transfer certificate revocation lists (CRLs) across Autonomic
Control Plane (ACP) channels. An unauthenticated, remote attacker can exploit this, by connecting an autonomic node
that has a known and revoked certificate to the autonomic domain of an affected system. The attacker can then insert a
previously trusted autonomic node into the autonomic domain of an affected system after the certificate for the node
has been revoked.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170726-anicrl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21f85a5a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd22328");
  script_set_attribute(attribute:"solution", value:
"No fixes are available for this vulnerability. For more information, see Cisco bug ID CSCvd22328");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.3bSP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.7.1',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1s',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '17.2.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['autonomic_networking'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvd22328',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
    product_info:product_info,
    workarounds:workarounds,
    workaround_params:workaround_params,
    reporting:reporting,
    vuln_versions:version_list
);
