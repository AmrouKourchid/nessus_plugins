#TRUSTED a3a2173e9ad87c79a1f0275f134739d37bf1af6e741d2cad5e749eb404035aab894e99a97c19a4fe1980e62ebae3a705791bdcfc77c6fcf9d10425fdf359bec635d7e25bbc71b9a922415bd9ea250ff4223f3a0775b3913496c3e53d1039066117f78bc0289e195ea6e2306da120cd3b84e8a2a0842d12c599006aecb724ac750c5fb628bd52375bedb7841d86666a0625080045ebae20361a2cd4f2c1ef0d5c66b5ceb90b4540ed30713f7bbd2f8d1b8851eee368d5419d8c30c4c41c7890af77b522de3e5a9cccfa7dc0b01362b5b760a62b4bfdedb0179710d45b2d14cb0dc216a6af9d2d860fee0b4ea86ee866669bea19b8c3c82dace05c86fb16f36112a0ed156fa91ab05f88a3812263a7aaf22e76471757048d042edf0a7ca775d8900d71d80605b7cea152f32a3b64cdf2f6bfcdfdbd5467d5ecc5ec5cf1c4496f4987313f3ef6cefa1ac3b0f6ef6b078b469a57e0fffdcabe0e3e92985b1d156fbe92c0c8dec6c40f74dc1d23882f0bb68766df64cfa95eb4067a279aced0a95604183be5f39dcb44a97448868a2447bf89961dec8ba9b01cf9f6cf70109355b8006415562800028a0f2e61a0d6d0925c8641da034a7c05b1a8c95c5b3caf1d452efbb5e1ddc9aee0a7ac934c94b52596e4101def576ec887d0808b5cc5e944d5f15e344b5bf0ea81233956ec09f496a72b24ffb765ff42cd0622b464960c466508
#TRUST-RSA-SHA256 a38f6a1a10849145430a2a2fd50d1147d441dee4afc7d243017c8139464d94a0394b6518250ff3e7911a9ef5569937d328b53e0e43a987c308f6046d0c58b75f6e5fd78197146cfab662b78ccfb6b99392077eab6e0c432d517b9d73f71e9539cf79044879a9e012b16c797b719512654b79cd7b9e160fb45acb283d7865f3e682b906713531084a185792e49b534bf4bc91bb85cd437bbf6c0ef2fff253f6bbf64931ea10324ecad686454e025ea3970773133c6ab9ccc2c95146c1e5707c5dba075d909209f4f0f46377ee0940bb672e440dee0f7c9131842c231aa77a7b2e89742cc830b0d1ada0bf300d65a79405c676eca64d9f1cc7d03a2f817b5dfebdd2a8b3c1c9cc47083d726847941383244b41bf08ca18237bba205d7f498141063c4615ea0bc358e5df186c33587514baaaf6313ddc45f8ddef255eb84bd7d47ded4ae04d58d9022661e82fb0a8c339d17f3c36b8d6382937bd4a5b5d0f0a4977281c8f3508ac96e0c9a1bdaa276360ef50aeaf849325922d4dfaeb109413f47ffd3d87d747e36e466f9899624cfad8259b4fc33606ee5fc43749196daa828862c5578151eaf631c891e80a4ad17f474654f64cc4e8f1697bdbc5d468fb66521c06c0a053496008f9d661d014ad0268911fd0b350c908c5424f3fd951ba2f3bc0c660dd6c4bb6e2b40fc6421a7264308c50bd42c1d6447830354ec2c23147aa1f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134304);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2013-7470");

  script_name(english:"Arista Networks EOS kernel DoS (SA0040)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability in
the Linux kernel. An unauthenticated, remote attacker can exploit this, by sending malformed packets with rarely used 
packet options to a vulnerable switch.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/7098-security-advisory-40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc9de589");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version EOS-4.18.11M / EOS-4.19.12.1M or later. Alternatively, apply the patch
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7470");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include('arista_eos_func.inc');

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
ext='SecurityAdvisory0040Hotfix.rpm 1.0.0/eng';
sha='7eea494a74245a06369ed11798bbcd13f6782932ee5586fb289ec6fc5dae4a300bc745a0aec4fb0e348d85d03c2aca37ad97c55313ced0f4c1632888944d2b1d';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');

vmatrix = make_array();
vmatrix['all'] =  make_list('4.14<=4.17.99');
vmatrix['F'] =    make_list('4.19.0',
                            '4.19.1',
                            '4.19.2',
                            '4.19.2.1',
                            '4.19.2.2',
                            '4.19.2.3',
                            '4.19.3',
                            '4.18.0',
                            '4.18.2',
                            '4.18.1.1',
                            '4.18.2',
                            '4.18.2.1',
                            '4.18.3.1',
                            '4.18.4',
                            '4.18.4.1',
                            '4.18.4.2',
                            '4.18.5');

vmatrix['M'] =    make_list('4.19.4',
                            '4.19.4.1',
                            '4.19.5',
                            '4.19.6',
                            '4.19.6.1',
                            '4.19.6.2',
                            '4.19.6.3',
                            '4.19.7',
                            '4.19.8',
                            '4.19.9',
                            '4.19.10',
                            '4.19.11',
                            '4.19.12',
                            '4.18.3',
                            '4.18.6',
                            '4.18.7',
                            '4.18.8',
                            '4.18.9',
                            '4.18.10');

vmatrix['fix'] = '4.18.11M / 4.19.12.1M';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
