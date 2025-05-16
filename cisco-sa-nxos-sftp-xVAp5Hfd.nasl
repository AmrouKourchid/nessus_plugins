#TRUSTED 6e14d361b9e4da5866e223df1c225eccc742feba293736e1897c608062a2be949f114aefaa01b330d0e2b13b409bf32e0ceba0577c0661e7dafe1ef5b8197f69bb2ec4a6cabb8a4bb113935ff5d6778dd2fed055b8c75beec08b76d8567fa79ba1dc7cd0710241f6a4b8cbd46543e5a452c82b817e725d037af7a92138dff531d7ab7db762c348e01e7d608fddf95d67d6baf16f895eb31b8676ac200d0332d95f28c5bb460c0c87e7e7b5692d0f7665bba9c801711878eabee18c46d70439e5bd63d48f46915d7362725f9d1947504ec975e922d0492b85aeb26d180810bb065d1616c997b8495889cff654f4e96374eb8fab7d47d97c1eb7d6ea81b920c1b91e851d0b62cf945a16325eed8a27f38496524657e389d19b93f2b23b6fee8884501e69b2b97c56cd614bed318989cc76968fd07c3a0903360f0bda9c1848d342bd05cf261ae726d86da7d8be66b3f1caa536ce056376fa457c0e7b1abe975d3e899f3a3bf29b3f2964d946768d098be5ab2dce271c25b52c1c6e01365bd8b18296526f6f60720e937ea54c5b0f9c3694d8816829fe47d8cefbb12e42b48730f9ad7be4640ca316f97dff2ad1500151008500a84b50fd1b0cf0329ffc2a1baef488803d4ac9a3b0fabe0c3aaa77701cf34901a1207a355b5dc3fd7f696c87b7a1eedaef91914ef5763f0600dcb48ff85a907f3748c6b742bc3dc8496f4e4ffdfe
#TRUST-RSA-SHA256 870060e0779cb24cb564f02df69709d8578d7af28ef909342fe7e49a9d72a607463bce1548b53f56ec5d68099d08ef43b57f9c6d0fe69847b2e872bdfd59cdd4a5c6b8bfd6185d16aa22ddc51aafc7080f2966a1c1e7b343fb84978f980a2410e5f2457b6445a412d10e5611e19d8aa71904c7bcf250ba925744f05c624f538aacbcf2c93218dfc80ac646d9b2681620e7797fed0d9d19a1261ce3ed183bf72b3c6c327fa5668fca46ce63b92bf34b7f0fbfeffb88fc97539c5a88d0fe76b5c3615c83e20be9b30a98eb0c9470491f5bce4c60e5d2ca61b134c31bdc8974efdec1ff21767a83105e3719602818c8c678d8c31692589a8dbb0b658207b0704f3ad8804a2aebd916b51caf21376987898f009a12b4ef88798ac07ced415f0e8abbd8b1c3bec20e9b6e7a1fb83a074d04cb791eba11811d0835a2d80321a6b65f2bedc1a80f7808cb5921ea7972cbdd74da22a89de0af80c5e5579da6df9d0a1e571de689cb59586cb4c839caf863b084d50a042813ba88609cf9d55417682f5f16c6dab9c84130dda3c41495fece85636e146b553c30c82d3e15d2a182086468c4038277941149c8d80cb3dfbb7478461f4d4928f54059bf232770dd4ab8ece4259b6c57b07fba7b5642b76d3222bc49625b36ee21d98cfae04dab6824c37e34402453587b7532bf8116f71f67126c17efe650965cdfcfc27bbe4b254a1ad2ee30
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180173);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/30");

  script_cve_id("CVE-2023-20115");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe47138");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-sftp-xVAp5Hfd");
  script_xref(name:"IAVA", value:"2023-A-0439");

  script_name(english:"Cisco Nexus 3000 9000 Series Switches SFTP Server File Access (cisco-sa-nxos-sftp-xVAp5Hfd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-sftp-xVAp5Hfd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd412dc7");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1feb9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe47138");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe47138");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var show_ver = get_kb_item('Host/Cisco/show_ver');
var smu_package;

if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

if (!empty_or_null(show_ver))
{
  foreach smu_package (['nxos.CSCwe47138-n9k_ALL-1.0.0-9.3.11.lib32_n9000',
                        'nxos64-cs.CSCwe47138-1.0.0-10.2.5.lib32_64_n9000',
                        'nxos64-msll.CSCwe47138-1.0.0-10.2.5.lib32_64_n9000'])
  {
    if (smu_package >< show_ver)
      audit(AUDIT_HOST_NOT, 'affected');
  }
}

var version_list = [];

if ('Nexus' >< product_info.device && product_info.model =~ "^3[0-9]{2,3}")
{
  version_list = make_list(
    '9.2(1)',
    '9.2(2)',
    '9.2(2t)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
    '9.2(2v)',
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
    '10.3(1)',
    '10.3(2)'
  );
}

if ('Nexus' >< product_info.device && product_info.model =~ "^9[0-9]{2,3}")
{
  version_list = make_list(
    '9.2(1)',
    '9.2(2)',
    '9.2(3)',
    '9.2(3y)',
    '9.2(4)',
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
    '10.3(2)'
  );
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe47138'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['inspect_sftp'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
