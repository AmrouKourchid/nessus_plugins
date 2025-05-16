#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194923);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2019-16942",
    "CVE-2019-16943",
    "CVE-2019-17531",
    "CVE-2019-20330",
    "CVE-2020-8840",
    "CVE-2020-9546",
    "CVE-2020-9547",
    "CVE-2020-9548",
    "CVE-2020-10650",
    "CVE-2020-10672",
    "CVE-2020-10673",
    "CVE-2020-10968",
    "CVE-2020-10969",
    "CVE-2020-11111",
    "CVE-2020-11112",
    "CVE-2020-11113",
    "CVE-2020-11619",
    "CVE-2020-11620",
    "CVE-2020-14060",
    "CVE-2020-14061",
    "CVE-2020-14062",
    "CVE-2020-14195",
    "CVE-2020-24616",
    "CVE-2020-25649",
    "CVE-2020-24750",
    "CVE-2020-35490",
    "CVE-2020-35491",
    "CVE-2020-35728",
    "CVE-2020-36182",
    "CVE-2020-36183",
    "CVE-2020-36184",
    "CVE-2020-36185",
    "CVE-2020-36186",
    "CVE-2020-36187",
    "CVE-2020-36188",
    "CVE-2020-36189",
    "CVE-2020-36518",
    "CVE-2021-20190",
    "CVE-2021-32559",
    "CVE-2022-41137",
    "CVE-2022-41725",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2023-5678",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24539",
    "CVE-2023-24540",
    "CVE-2023-28319",
    "CVE-2023-28320",
    "CVE-2023-28321",
    "CVE-2023-28322",
    "CVE-2023-29400",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405",
    "CVE-2023-29409",
    "CVE-2023-38039",
    "CVE-2023-38546",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39320",
    "CVE-2023-39323",
    "CVE-2023-39325",
    "CVE-2023-39326",
    "CVE-2023-46218",
    "CVE-2023-46219",
    "CVE-2024-0727",
    "CVE-2024-0853",
    "CVE-2024-2004",
    "CVE-2024-2398",
    "CVE-2024-2466",
    "CVE-2024-7264",
    "CVE-2024-8096",
    "CVE-2024-9681",
    "CVE-2024-11053",
    "CVE-2024-29869",
    "CVE-2025-0725",
    "CVE-2025-0167"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Splunk Enterprise 9.0.0 < 9.0.9, 9.1.0 < 9.1.4, 9.2.0 < 9.2.1 (SVD-2024-0303)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2024-0303 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2024-0303.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to versions 9.2.1, 9.1.4, and 9.0.9, or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20190");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-39320");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.9', 'license' : 'Enterprise' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.4', 'license' : 'Enterprise' },
  { 'min_version' : '9.2.0', 'fixed_version' : '9.2.1', 'license' : 'Enterprise' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
