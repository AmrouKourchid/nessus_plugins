#TRUSTED 226ae81b7aeb19a7554ade6f06848313e4bbc4a84be02738c5ed3dd480f5521ea13e02c56324102e67677cddaaf11ed0148202542db2ce0de9463d525c893257d9574cebce28e180811857c72f5fbad630f7a3ea451f3b9528a12ec010771375b6c58fa6e4750dcafb8ad20d527931d8e3406bc6dd7f11feeeed8bfd6a1627db0639cd22d2172ce0107411e120684635d7a75dd1ebb853b1186bd55498dd4542470f7417644b02406f64761f3147275c41adb5dc4b6d9aae8fc229999317a25a7d9c1b02794a219e7f55f87289fafe4718a57c60bc928e8876394b622a810b6445ce7578ba9ea0ba6f5d91e26c55abd49872c21555a386e532f111ff4c09b3b2d62e98bab5b385ac2cf18f8242f2902e837b18849a31b1de364b44e95f99a80c99422e385313ab96615a29e527d86c959fcb5b5ba408f59e147da93ff97939e3eb5749a70036a55545832ba328b8beea68fb6a96d9edfe483354ef0a2d95fdd1253b984e2e6248e8d64154e8e613d58f1d586bf32e0a449323a580d3701da145ad820f7c89a702896808c52ef19e723ba58f2cb10d52cb5d2db29ae5e061769c886d95a6e880c0eba1e61cf53433dbb923c1060d40ac7cc58aa50dc9b5bb345638608f228a502290f7e2d9d3beaead10b563488cc45c13a85648c9337ba54b6749c4b9ba2158677823b9e5e4a412005c020f32029846473320b7fef59bc6eeb4
#TRUST-RSA-SHA256 846db76a240454b587d2491f1840e72614bac8252c9953d1cc597a8c50b6365ef3edcd12b6261a0a343cc9e11323c9722bb6c907c5336f97b514223a1ea786fb7b128eac30d1e00c679610b5a5ec23c0aae75d03744f396c0e5567bc65b43bb7f69bee1a165d9ba19f56247379f7ca33306451bf40ec66b77d626fd7116041ddf4e3bf4f14b3e3e362c17020f8e3e73963f491f32d04688e1c5f014db23d48d87cb6b6a6244f66c2a3171cd2f4003a6c058d506cae265ac0be20dd882bc6385e323d71530b6159f3e945f55204b16d9182826c737acde0d73c17293544fe765db1bebf9b5b0e4a9065488f7e890af5f633b6ef3fc3ccf6eb64b168e62cc1c2aad811d688450340449bb8386b3a998574aea2e92ee3d7b344405e770710a879f5fce6fc6bf542abcd13078cfe6aebaead4fbf31a90ceecf33faafac39b4fb99cd092126b67e0b996214daa85f687a324e042027b7851709add09e15fe7aa7dced60e22c6bb6833ff57c05f1e941cbf3dff37d9944bec6f4d4b7a844d1639b72411f9d3a024f100c2decbea8f4fdecb5e07cdc040d391c7cd055a3ca645a3e8446f6ab9924a03131041e20f8889df361d5b971c501e13e8df82f5d4dae65154c0f1a2fd215d407521c250f838cd23158dac5ff8e41495a40abface3169510466db04424f1c489fdfa2197bac1433050d1c8547714707f51ba3066ec6e3fcdceea1

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(204872);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_name(english:"Integration Status");

  script_set_attribute(attribute:"synopsis", value:
                       "The purpose of this plugin is to provide the user with helpful information regarding the success or failure when using one of Tenable's
                       with any PAM, MDM, and/or Patch Management Integrations.");
  script_set_attribute(attribute:"description", value:"The following Integration was used and here are the results.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/31");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_exclude_keys("Host/ping_failed", "Host/dead");

  exit(0);
}

include("integrations_common.inc");


integrations::status::gather_credentials();

# To ensure this plugin does not cause license issues on SC
# versions older than 6.6, audit out if SC version < 6.6
var sc_version = integrations::get_sc_version();
if (sc_version)
{
  var split_sc_version = split(sc_version, sep:'.', keep:FALSE);
  var sc_major = int(split_sc_version[0]);
  var sc_minor = int(split_sc_version[1]);
  if (sc_major < 6 || sc_major == 6 && sc_minor < 6)
  {
    exit(0, "Not executing Integration Status on SecurityCenter pre-6.6. SC version: " + sc_version);
  }
}

var report = integrations::status::process_report_data();
if (report)
{
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
