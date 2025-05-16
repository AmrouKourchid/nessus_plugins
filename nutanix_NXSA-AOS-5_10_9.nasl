#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164581);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2016-3186",
    "CVE-2016-3616",
    "CVE-2016-10739",
    "CVE-2016-10745",
    "CVE-2018-0495",
    "CVE-2018-0734",
    "CVE-2018-1122",
    "CVE-2018-3058",
    "CVE-2018-3063",
    "CVE-2018-3066",
    "CVE-2018-3081",
    "CVE-2018-3282",
    "CVE-2018-5741",
    "CVE-2018-7456",
    "CVE-2018-8905",
    "CVE-2018-10689",
    "CVE-2018-10779",
    "CVE-2018-10963",
    "CVE-2018-11212",
    "CVE-2018-11213",
    "CVE-2018-11214",
    "CVE-2018-11813",
    "CVE-2018-12327",
    "CVE-2018-12404",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12900",
    "CVE-2018-14348",
    "CVE-2018-14498",
    "CVE-2018-14598",
    "CVE-2018-14599",
    "CVE-2018-14600",
    "CVE-2018-14618",
    "CVE-2018-14647",
    "CVE-2018-15473",
    "CVE-2018-15686",
    "CVE-2018-15853",
    "CVE-2018-15854",
    "CVE-2018-15855",
    "CVE-2018-15856",
    "CVE-2018-15857",
    "CVE-2018-15859",
    "CVE-2018-15861",
    "CVE-2018-15862",
    "CVE-2018-15863",
    "CVE-2018-15864",
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-16403",
    "CVE-2018-16842",
    "CVE-2018-16866",
    "CVE-2018-16888",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-18074",
    "CVE-2018-18310",
    "CVE-2018-18384",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2018-18557",
    "CVE-2018-18584",
    "CVE-2018-18585",
    "CVE-2018-18661",
    "CVE-2018-19788",
    "CVE-2018-20060",
    "CVE-2018-1000876",
    "CVE-2019-0217",
    "CVE-2019-0220",
    "CVE-2019-1559",
    "CVE-2019-2503",
    "CVE-2019-2529",
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-3858",
    "CVE-2019-3861",
    "CVE-2019-5010",
    "CVE-2019-6470",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7664",
    "CVE-2019-7665",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948",
    "CVE-2019-11236",
    "CVE-2019-12735",
    "CVE-2019-1010238"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.10.9)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.10.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.10.9 advisory.

  - curl before version 7.61.1 is vulnerable to a buffer overrun in the NTLM authentication code. The internal
    function Curl_ntlm_core_mk_nt_hash multiplies the length of the password by two (SUM) to figure out how
    large temporary storage area to allocate from the heap. The length value is then subsequently used to
    iterate over the password and generate output into the allocated storage buffer. On systems with a 32 bit
    size_t, the math to calculate SUM triggers an integer overflow when the password length exceeds 2GB (2^31
    bytes). This integer overflow usually causes a very small buffer to actually get allocated instead of the
    intended very huge one, making the use of that buffer end up in a heap buffer overflow. (This bug is
    almost identical to CVE-2017-8816.) (CVE-2018-14618)

  - Gnome Pango 1.42 and later is affected by: Buffer Overflow. The impact is: The heap based buffer overflow
    can be used to get code execution. The component is: function name: pango_log2vis_get_embedding_levels,
    assignment of nchars and the loop condition. The attack vector is: Bug can be used when application pass
    invalid utf-8 strings to functions like pango_itemize. (CVE-2019-1010238)

  - Buffer overflow in the readextension function in gif2tiff.c in LibTIFF 4.0.6 allows remote attackers to
    cause a denial of service (application crash) via a crafted GIF file. (CVE-2016-3186)

  - TIFFWriteScanline in tif_write.c in LibTIFF 3.8.2 has a heap-based buffer over-read, as demonstrated by
    bmp2tiff. (CVE-2018-10779)

  - The TIFFWriteDirectorySec() function in tif_dirwrite.c in LibTIFF through 4.0.9 allows remote attackers to
    cause a denial of service (assertion failure and application crash) via a crafted file, a different
    vulnerability than CVE-2017-13726. (CVE-2018-10963)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.10.9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a252356e");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14618");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1010238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.10.9', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.10.9 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.10.9', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.10.9 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
