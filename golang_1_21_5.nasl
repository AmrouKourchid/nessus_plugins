#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186690);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2023-39326", "CVE-2023-45285");
  script_xref(name:"IAVB", value:"2023-B-0096-S");

  script_name(english:"Golang 1.20.x < 1.20.12, 1.21.x < 1.21.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang running on the remote host is prior to 1.20.12 or 1.21.x prior to 1.21.5. It is, therefore, is
affected by multiple vulnerabilities :

  - A malicious HTTP sender can use chunk extensions to cause a receiver reading from a request or response
    body to read many more bytes from the network than are in the body. A malicious HTTP client can further
    exploit this to cause a server to automatically read a large amount of data (up to about 1GiB) when a
    handler fails to read the entire body of a request. Chunk extensions are a little-used HTTP feature
    which permit including additional metadata in a request or response body sent using the chunked
    encoding. The net/http chunked encoding reader discards this metadata. A sender can exploit this by
    inserting a large metadata segment with each byte transferred. The chunk reader now produces an error
    if the ratio of real body to encoded bytes grows too small. (CVE-2023-39326)

  - Using go get to fetch a module with the '.git' suffix may unexpectedly fallback to the insecure 'git://'
    protocol if the module is unavailable via the secure 'https://' and 'git+ssh://' protocols, even if
    GOINSECURE is not set for said module. This only affects users who are not using the module proxy and
    are fetching modules directly (i.e. GOPROXY=off). (CVE-2023-45285)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/golang-dev/c/6ypN5EjibjM/m/KmLVYH_uAgAJ");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.20.12, 1.21.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45285");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '1.20.12' },
  { 'min_version' : '1.21', 'fixed_version' : '1.21.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);