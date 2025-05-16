#TRUSTED 3b189095f631ade25b039e2f16689a2cc97a021d8f5d1491e66a6f9c0f542787494bf51348e9ad77f9d17137c95fcd88b5d08064a73fcfcfc3177504cbb1ee650ac347fa21bd75c7183300a0e71c883849044da686c3b3246d8d00218a17f9726f38b7a8314c499c5342eb2473704e4f3f456e14f721d14b6252de152caa843bd0f6e7c10e44bde70f6d70982429249db68e605b6fe34c9f43b3900a5ddd9ceec7d40637cbf9ec454238c43527bdc2a1ca9f6128e519099155094f1bfdc4ade590320046d2ca06bcc3d45cec7f9e84b7dcf60b746d99386e80753c2af84c03e6373643062bcd0625a731986c458e108792af21ad64f545185710603295fb02301872aa69e00d2e73536ff03550c4f0d23b77a34e31205577751bac1fb2c09a6dbc69506ca481cdbc5d8282d905775079a72dfa3248f4d741783d24e90856047ae19791cafab63951dca9914c0631f4059ff41631bb7b50770f43977871b159b5860ef3a7a466bac98f5026a5f3ca3b5323791af75c3cc7cfc5a57c7a02deb0f32b8baa9f6d4788d7f61607ca2932afc51c12fafde4ddc1690695e6cc963d15154900a0216db8e0303be909edf19a9e9de61f96a0a90a9c0a4ee3427d471d0bb449aee3c81e5c3451d7e680570b83f1002321662d38488871c7fe152a5ad097af1e0b13061ef19a8800262dce166830a61df15be8609d31062c06665240d86bee
#TRUST-RSA-SHA256 3dd1be7e1a8a802866198bfcd2ebf9fac1e3f1c64d6c38b9921a1899e240a9fff32f4ba6c6bdbc57f61d18a3654dd0ead02fc3d43fe2162e9dbfd65dfd3617db79decaa1e920969753b5b169def65b0fcdcf19f4e27c4897db4fed103b78b12ae4a2f8aca0cfb10ab519a25d09a89efae2938fe363dda26e9b76e41a007a23349eb58aac11946c3d050a199770522215f1fb7f1db70c19858ca9bedc7b97a5fc0632be94801dda96ae792f15c38f5bb9957957318fe0fe95058cde7ef29cb7a012c0e3ee69393106d47205367f926fb1dcbd3fa70812b354105d76a85808f9fe23405cccc9e94f05e5f153773e8a6a6c6d0bf8994938eb437d2b7fcf9379d7a1d68b61fedded3a040e708c6f8f77e4f3211770b89cac03b18f94b76fd7326649283bc4e42194a6ee44d7175df6e05457e945045b1c9072a4db6f961097c4397a71fbc6ef23234ce0fbc0568b4b81c113f8e59970d46c1daabae8783b5bf2339ec720c980b389f7e4b9a7db218d22cd8bd3b8dd4c03954a7836fa36cfd78ff72c208feb575b956c91e775b852f56f1da25e18dd33b7554e8e5ca7cfe8f9df6b9e46bfb80a0f138497d7d33b2045b8ccde43bf9a198493a01479ffd9afaf66348efab26945ef48257cc6a04f15cb5eaa2af89f92c8e8a90a0a2f4ce714cfdc3b88e72bb2d3098b0b94f6b8fb7633ebee74b8539c5a4bb1dc35652dd6fd4a8c6882
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183725);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/24");

  script_cve_id("CVE-2023-44181");
  script_xref(name:"JSA", value:"JSA73145");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73145)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73145
advisory.

  - An Improperly Implemented Security Check for Standard vulnerability in storm control of Juniper Networks
    Junos OS QFX5k devices allows packets to be punted to ARP queue causing a l2 loop resulting in a DDOS
    violations and DDOS syslog. (CVE-2023-44181)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73145");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-QFX5k-l2-loop-in-the-overlay-impacts-the-stability-in-a-EVPN-VXLAN-environment-CVE-2023-44181
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c653da6a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73145");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^QFX5(k|\d\d\d)")
  audit(AUDIT_DEVICE_NOT_VULN, model);

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0',    'fixed_ver':'20.2R3-S6'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S5'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S2'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  if (!junos_check_config(buf:buf, pattern:"^set forwarding-options set storm-control-profiles .+"))
    audit(AUDIT_HOST_NOT, "affected because no storm-control profile is set");
  if (!junos_check_config(buf:buf, pattern:"^set interfaces .+ storm-control .+"))
    audit(AUDIT_HOST_NOT, "affected because no interface has an associated storm-control profile");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
