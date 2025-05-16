#TRUSTED 626326381ea7c8b27f9ad9260ad303c2f5dafb741118cf1dcf45af4f9e6695095c3602d10a5ca6c57c8260faa21a991d20053cda643558179941503998a44943b16030b827b51f93fbbfa357f13292f5af015d7576c2bdcd9cada327249c6852d49b528936d79a5eb7fd964a932b4b0cf8c1e489dec5a15cbc65bdda7c2b7d1cd303ec30c9d7570871bc0d14ab83675f3b28eb567a7833c6951afa07046a29ed2169b69afd7b80109a4337399e1d00886563938d1d7c200d2dcac195953f8f657c6656f5afa4f5e81b041136903dd50cb151e412bea2e76bac5199d987743b25c31ae825670c3edb3832eb83b8e55383ac922207ad0247f58aa11766958ae156e307e4b6051e65d35729fb2c70ac2ee97f0a083a5d3fc7285db33ed3e68d14cdce429e6586144f4961313c24b56fefb2b3f071765a2795cab79ad23aa8188ec785545f242b8b5e2e45151b51a26b462c2abd040083fb24f56b29e6cab553e0bd64ecca2d826b4340d9e8c93196fbbdeabf89c630170c4cf04f276d7a1533ba7b69e946cef96651764755aff4ab6c4d0497f7c8cf9af1aa267674c2b3546e8f9c7e5860ace80286dd22e941ec6eeb149b920cd07b68dfb22adde55a9c0f4f8d3c44eac609e46ee00cfafea2231bee79a2e4815392821935778823c5c343dcc38d18e1280dc59500d587196c7261f4496acd0acf197f7b6e9f4d5989cfeb584bfb
#TRUST-RSA-SHA256 9549c0879507c74aa96627fac7348a9cfd706ed3bdb9398709051949c1d486bda91cee7dcf6ea3a1db3524d43bfedbe32c0192f7e3ffcfd9c9ca161638edfa23191affc8ec6525f665949baf412e9ed8c1ea70a963f0cee9eebd32bbf210de3150d649b55f11a5b12760c4b7a928ceb3875546bbd872ac519a95c29e630d852a524afbee365bf2685d8a74be0ae7aa34e6424ecced5afa7b9438ed0f9e3bac13367c7e89f9642b9c2c1d2f77c24ee27c981cfb4eeec4a6af5d0b552d287f63236f8ecceb45a15d42748ebac09132769ceb7f08401aa4e0dc2862f3dc286478508386588ba2f960aad1ebd22d43b0b4f5044818e334473f7f15ff2276f31a9db3cfb9bddad8050419ec5c60d1e33b1727ca08f65c2ec51e84e0fafd54ac029fa2ef3a93ac3d4ced5ed5f0a8dc139975bccc373615b40fa2778011cff9bc988f92ecc8caf69ee10aa32c75fb4f94288c2653b22cb576c0f4cd0649a05b0bb01553d4471be6e744e63a59c1c298c6e43effa516a1392fcf653b1bf06f9cdd29ea09fcd62777945783d98e2f5182efd41596aff4abe0c636b38543e14d99a9493b3f8bb6d68a4a0d4c3f2873dcf454cc8289026af4c1609fa7229ae1e1702faf8c77922b100f1d010495157cea3ff694ecfc24197d83ff4ca8b6601e35834a4735f379270c863b4dac8d278cf154d36128b73814766cbc2bdd825f392a458d4e8838
#
# (C) Tenable, Inc.
#

if (NASL_LEVEL < 6900) exit(0);

include("compat.inc");

if (description)
{
  script_id(96797);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/20");

  script_name(english:"Host Asset Information");
  script_summary(english:"Displays information about the scan.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed
software, users, and user groups on the target host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host including:
  - network interfaces including IP addresses, MAC addresses, FQDNs
  - inventory of installed software
  - information about users and user groups

This data has been stored in the Nessus report database.

Note that this plugin will not produce a visible report in the Nessus
user interface.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies('ip_assignment_method.nbin', 'asset_attribute_fqdn.nasl', 'ethernet_manufacturer.nasl');
  script_exclude_keys("Host/dead");

  exit(0);
}

include('agent.inc');
include('host_summary.inc');

if(get_kb_item("Host/dead") == TRUE) exit(0, "Host is offline.");

# Without this function, the plugin does nothing useful
if (!defined_func("report_tag_internal"))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');

#Double the preset memory limit for this plugin since it has a history of exceeding 80MB
if (defined_func("set_mem_limits"))
  set_mem_limits(max_alloc_size:160*1024*1024, max_program_size:160*1024*1024);

enumerate_interfaces();
enumerate_software();
enumerate_users();
enumerate_groups();
enumerate_misc();
enumerate_cpes();

enumerate_out_of_range_ports();
