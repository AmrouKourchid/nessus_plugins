#TRUSTED 41b5df6c6ba44ec2b267231108a7f57a5511da10cae651ea12b8ad879d85d01184214b54923a44988a1db7ec5371dd05736bcea51e2e211f3b2770023d5a077358483cb5eb7ca1d589e206d5fda7b7324f642a68758b582b6ccaf4eb38d85200985d1e0793a86ce7bdd122a806e91614bf8792c900e7e119b723d3b8ad823bf80e35215270c535d6081cf322ae4ab6853f0b8d9126f3b8351330105cdad8bb9ef83d3374f85bf6a1549c285b588c7ede08e984a85af2bac2a1412fdb548e5d4b4a5e01e8b734af7e8be2e2e219aaa17d32cc2df8f88ca333442f6ecdfe4a9af182c3b469dd62df0d091beea9c76a3192cc320372ab294c5471be0bbcdadd90ed1beed28f9aa1d5cfb44ed73bf0d9572884fa49341a9b71fb2dcfa3ec411416b422eb5e8971d8dfd7f689075e94edf865cbb0df0df3b90baba48d9f67d1f10e5560b4917f37f8d9f7c7bf4928d2df3f8c8f611bb4c79d7513f013c359a2dab5ccd1dd283e69b4e1fb3aae0e45da9e1b541fb30a41b88765d88b3ba3d2016d68f3db18103b5f37d9e60b233796a9b4450ae0dd6ce6170765dda7ed3052ffb7ed3fc697228dcc62238d15157144da170fea962d60e26d8c2ac247171767dbe3145407c891ddfbbf40a447858bbc6dba31c5d968e1ae26162b0620e25784409eacdcd8d57c7f2be42f01bd08fd5244f933a8ffada0d164593893d06da8bf6560e13e
#TRUST-RSA-SHA256 5deaa0808cf1820746fc286b110c6ed8d33dcbab02c500be26309927aa3b60c574c9adf4ac2625d0b3275c19b1ceb835240c8efc606270a657f3a369aa0b447119114a02698d319888ff10f59c0f5340f652dd35c14c58fb8bd2d9ab30aa8c7c434d7a11a840fb7a97c949ea25f76f94055159d535a32619a8c8e488b10f0036b7b9e5a3c7f5318df57272854321eed8f75e66f69ef571573d6f98ca7c404d6f9d2e943ca2e04ce3b6f5b796334c0bdb5728c0b0d8b6d9055e89ede0191804af4317a4300b86c0ffc8d115aea660b3393d89667de4841f88ccbc8e4cb7250834468aa0dd5f3a4c19d979f88423d0f5b16ccb4b2b27918025237be062fd7a56a897ed9a8ede839cc9019ee11c521da43b81615b0ba3dfd02d7a74e59315d2feeb73413c7ac67d8308cdb34327dc329ef5ac3ae71f64dfbd2047a8156dfd7086d805b7313277cc1e210500cefb79c9b79511ab046fb50448a49992c845332ec0579f4b2f94c2e3dcdfd825fc639d9461cbca1289abdba0f9205f95323a9bc58a15221c7548acefc679a58c15035f92d7d44a51425b766ce286b830ee18400251eb90f8427eb1c817f8701ac560a1babd36d98afd1c877597d5ec59b451651c8684306ce2481c6fa62f62c04bf913c3aa700d5839a8e555979ae571a3ae83df6d097e0a8bcc968374213d1e60f17905b9f277e118bc4721abc1f31f5b93ce892148
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2023-20117", "CVE-2023-20128");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe57193");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe63677");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv32x-cmdinject-cKQsZpxL");

  script_name(english:"Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers Command Injection Vulnerabilities (cisco-sa-sb-rv32x-cmdinject-cKQsZpxL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers are affected
by multiple command injection vulnerabilities. Multiple vulnerabilities in the web-based management interface of Cisco
Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker to inject and
execute arbitrary commands on the underlying operating system of an affected device. These vulnerabilities are due to
insufficient validation of user-supplied input. An attacker could exploit these vulnerabilities by sending malicious
input to an affected device. A successful exploit could allow the attacker to execute arbitrary commands as the root
user on the underlying Linux operating system of the affected device. To exploit these vulnerabilities, an attacker
would need to have valid Administrator credentials on the affected device. Cisco has not released software updates to
address these vulnerabilities.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv32x-cmdinject-cKQsZpxL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bc4b1f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe57193");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe63677");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe57193, CSCwe63677");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20128");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv325");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) !~ "^RV32[05]")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwe57193, CSCwe63677',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);


cisco::security_report_cisco_v2(reporting:reporting);

