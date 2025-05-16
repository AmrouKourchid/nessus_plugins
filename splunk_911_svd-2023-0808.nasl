#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(194928);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_cve_id(
    "CVE-2013-7489",
    "CVE-2018-10237",
    "CVE-2018-20225",
    "CVE-2019-20454",
    "CVE-2019-20838",
    "CVE-2020-8169",
    "CVE-2020-8177",
    "CVE-2020-8231",
    "CVE-2020-8284",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2020-8908",
    "CVE-2020-14155",
    "CVE-2020-28469",
    "CVE-2020-28851",
    "CVE-2020-29652",
    "CVE-2021-3520",
    "CVE-2021-3572",
    "CVE-2021-3803",
    "CVE-2021-20066",
    "CVE-2021-22569",
    "CVE-2021-22876",
    "CVE-2021-22890",
    "CVE-2021-22897",
    "CVE-2021-22898",
    "CVE-2021-22901",
    "CVE-2021-22922",
    "CVE-2021-22923",
    "CVE-2021-22924",
    "CVE-2021-22925",
    "CVE-2021-22926",
    "CVE-2021-22945",
    "CVE-2021-22946",
    "CVE-2021-22947",
    "CVE-2021-23343",
    "CVE-2021-23382",
    "CVE-2021-27918",
    "CVE-2021-27919",
    "CVE-2021-29060",
    "CVE-2021-29425",
    "CVE-2021-29923",
    "CVE-2021-31525",
    "CVE-2021-31566",
    "CVE-2021-33194",
    "CVE-2021-33195",
    "CVE-2021-33196",
    "CVE-2021-33197",
    "CVE-2021-33198",
    "CVE-2021-34558",
    "CVE-2021-36221",
    "CVE-2021-36976",
    "CVE-2021-38297",
    "CVE-2021-38561",
    "CVE-2021-39293",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2021-41771",
    "CVE-2021-41772",
    "CVE-2021-43565",
    "CVE-2021-44716",
    "CVE-2021-44717",
    "CVE-2022-1705",
    "CVE-2022-1941",
    "CVE-2022-1962",
    "CVE-2022-2309",
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-3171",
    "CVE-2022-3509",
    "CVE-2022-3510",
    "CVE-2022-3517",
    "CVE-2022-22576",
    "CVE-2022-23491",
    "CVE-2022-23772",
    "CVE-2022-23773",
    "CVE-2022-23806",
    "CVE-2022-24675",
    "CVE-2022-24921",
    "CVE-2022-24999",
    "CVE-2022-25881",
    "CVE-2022-27191",
    "CVE-2022-27536",
    "CVE-2022-27664",
    "CVE-2022-27774",
    "CVE-2022-27775",
    "CVE-2022-27776",
    "CVE-2022-27778",
    "CVE-2022-27779",
    "CVE-2022-27780",
    "CVE-2022-27781",
    "CVE-2022-27782",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-29804",
    "CVE-2022-30115",
    "CVE-2022-30580",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30634",
    "CVE-2022-30635",
    "CVE-2022-31129",
    "CVE-2022-32148",
    "CVE-2022-32149",
    "CVE-2022-32189",
    "CVE-2022-32205",
    "CVE-2022-32206",
    "CVE-2022-32207",
    "CVE-2022-32208",
    "CVE-2022-32221",
    "CVE-2022-33987",
    "CVE-2022-35252",
    "CVE-2022-35260",
    "CVE-2022-35737",
    "CVE-2022-36227",
    "CVE-2022-37599",
    "CVE-2022-37601",
    "CVE-2022-37603",
    "CVE-2022-38900",
    "CVE-2022-40023",
    "CVE-2022-40897",
    "CVE-2022-40899",
    "CVE-2022-41715",
    "CVE-2022-41716",
    "CVE-2022-41720",
    "CVE-2022-41722",
    "CVE-2022-42003",
    "CVE-2022-42004",
    "CVE-2022-42915",
    "CVE-2022-42916",
    "CVE-2022-43551",
    "CVE-2022-43552",
    "CVE-2022-46175",
    "CVE-2023-23914",
    "CVE-2023-23915",
    "CVE-2023-23916",
    "CVE-2023-24539",
    "CVE-2023-24540",
    "CVE-2023-27533",
    "CVE-2023-27534",
    "CVE-2023-27535",
    "CVE-2023-27536",
    "CVE-2023-27537",
    "CVE-2023-27538",
    "CVE-2023-29400",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29405"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"Splunk Enterprise 8.2.0 < 8.2.12, 9.0.0 < 9.0.6, 9.1.0 < 9.1.1 (SVD-2023-0808)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Splunk installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the SVD-2023-0808 advisory.

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. Flags containing embedded spaces are
    mishandled, allowing disallowed flags to be smuggled through the LDFLAGS sanitization by including them in
    the argument of another flag. This only affects usage of the gccgo compiler. (CVE-2023-29405)

  - When curl < 7.84.0 saves cookies, alt-svc and hsts data to local files, it makes the operation atomic by
    finalizing the operation with a rename from a temporary name to the final target file name.In that rename
    operation, it might accidentally *widen* the permissions for the target file, leaving the updated file
    accessible to more users than intended. (CVE-2022-32207)

  - decode-uri-component 0.2.0 is vulnerable to Improper Input Validation resulting in DoS. (CVE-2022-38900)

  - The got package before 12.1.0 (also fixed in 11.8.5) for Node.js allows a redirect to a UNIX socket.
    (CVE-2022-33987)

  - Prototype pollution vulnerability in function parseQuery in parseQuery.js in webpack loader-utils via the
    name variable in parseQuery.js. This affects all versions prior to 1.4.1 and 2.0.3. (CVE-2022-37601)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://advisory.splunk.com/advisories/SVD-2023-0808.html");
  script_set_attribute(attribute:"solution", value:
"For Splunk Enterprise, upgrade versions to 8.2.12, 9.0.6, or 9.1.1.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32207");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-29405");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin", "splunk_nix_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'min_version' : '8.2.0', 'fixed_version' : '8.2.12', 'license' : 'Enterprise' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.6', 'license' : 'Enterprise' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.1', 'license' : 'Enterprise' }
];
vcf::splunk::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
