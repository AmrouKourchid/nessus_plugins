#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4255-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212310);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2023-31315");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4255-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel-firmware (SUSE-SU-2024:4255-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2024:4255-1 advisory.

    - Update to version 20241128 (git commit ea71da6f0690):
      * i915: Update Xe2LPD DMC to v2.24
      * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for various Dell laptops
      * iwlwifi: add Bz-gf FW for core89-91 release
      * amdgpu: update smu 13.0.10 firmware
      * amdgpu: update sdma 6.0.3 firmware
      * amdgpu: update psp 13.0.10 firmware
      * amdgpu: update gc 11.0.3 firmware
      * amdgpu: add smu 13.0.14 firmware
      * amdgpu: add sdma 4.4.5 firmware
      * amdgpu: add psp 13.0.14 firmware
      * amdgpu: add gc 9.4.4 firmware
      * amdgpu: update vcn 3.1.2 firmware
      * amdgpu: update psp 13.0.5 firmware
      * amdgpu: update psp 13.0.8 firmware
      * amdgpu: update vega20 firmware
      * amdgpu: update vega12 firmware
      * amdgpu: update psp 14.0.4 firmware
      * amdgpu: update gc 11.5.2 firmware
      * amdgpu: update vega10 firmware
      * amdgpu: update vcn 4.0.0 firmware
      * amdgpu: update smu 13.0.0 firmware
      * amdgpu: update psp 13.0.0 firmware
      * amdgpu: update gc 11.0.0 firmware
      * amdgpu: update beige goby firmware
      * amdgpu: update vangogh firmware
      * amdgpu: update dimgrey cavefish firmware
      * amdgpu: update navy flounder firmware
      * amdgpu: update psp 13.0.11 firmware
      * amdgpu: update gc 11.0.4 firmware
      * amdgpu: update vcn 4.0.2 firmware
      * amdgpu: update psp 13.0.4 firmware
      * amdgpu: update gc 11.0.1 firmware
      * amdgpu: update sienna cichlid firmware
      * amdgpu: update vpe 6.1.1 firmware
      * amdgpu: update vcn 4.0.6 firmware
      * amdgpu: update psp 14.0.1 firmware
      * amdgpu: update gc 11.5.1 firmware
      * amdgpu: update vcn 4.0.5 firmware
      * amdgpu: update psp 14.0.0 firmware
      * amdgpu: update gc 11.5.0 firmware
      * amdgpu: update navi14 firmware
      * amdgpu: update arcturus firmware
      * amdgpu: update renoir firmware
      * amdgpu: update navi12 firmware
      * amdgpu: update sdma 4.4.2 firmware
      * amdgpu: update psp 13.0.6 firmware
      * amdgpu: update gc 9.4.3 firmware
      * amdgpu: update vcn 4.0.4 firmware
      * amdgpu: update psp 13.0.7 firmware
      * amdgpu: update gc 11.0.2 firmware
      * amdgpu: update navi10 firmware
      * amdgpu: update aldebaran firmware
    - Update aliases from 6.13-rc1

    - Update to version 20241125 (git commit 508d770ee6f3):
      * ice: update ice DDP wireless_edge package to 1.3.20.0
      * ice: update ice DDP comms package to 1.3.52.0
      * ice: update ice DDP package to ice-1.3.41.0
      * amdgpu: update DMCUB to v9.0.10.0 for DCN314
      * amdgpu: update DMCUB to v9.0.10.0 for DCN351

    - Update to version 20241121 (git commit 48bb90cceb88):
      * linux-firmware: Update AMD cpu microcode
      * xe: Update GUC to v70.36.0 for BMG, LNL
      * i915: Update GUC to v70.36.0 for ADL-P, DG1, DG2, MTL, TGL

    - Update to version 20241119 (git commit 60cdfe1831e8):
      * iwlwifi: add Bz-gf FW for core91-69 release
    - Update aliases from 6.12

    - Update to version 20241113 (git commit 1727aceef4d2):
      * qcom: venus-5.4: add venus firmware file for qcs615
      * qcom: update venus firmware file for SC7280
      * QCA: Add 22 bluetooth firmware nvm files for QCA2066

    - Update to version 20241112 (git commit c57a0a42468b):
      * mediatek MT7922: update bluetooth firmware to 20241106163512
      * mediatek MT7921: update bluetooth firmware to 20241106151414
      * linux-firmware: update firmware for MT7922 WiFi device
      * linux-firmware: update firmware for MT7921 WiFi device
      * qcom: Add QDU100 firmware image files.
      * qcom: Update aic100 firmware files
      * dedup-firmware.sh: fix infinite loop for --verbose
      * rtl_bt: Update RTL8852BT/RTL8852BE-VT BT USB FW to 0x04D7_63F7
      * cnm: update chips&media wave521c firmware.
      * mediatek MT7920: update bluetooth firmware to 20241104091246
      * linux-firmware: update firmware for MT7920 WiFi device
      * copy-firmware.sh: Run check_whence.py only if in a git repo
      * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for various Dell laptops
      * amdgpu: update DMCUB to v9.0.10.0 for DCN351
      * rtw89: 8852a: update fw to v0.13.36.2
      * rtw88: Add firmware v52.14.0 for RTL8812AU
      * i915: Update Xe2LPD DMC to v2.23
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7925)
      * linux-firmware: update firmware for MT7925 WiFi device
      * WHENCE: Add sof-tolg for mt8195
      *  linux-firmware: Update firmware file for Intel BlazarI core
      * qcom: Add link for QCS6490 GPU firmware
      * qcom: update gpu firmwares for qcs615 chipset
      * cirrus: cs35l56: Update firmware for Cirrus Amps for some HP laptops
      * mediatek: Add sof-tolg for mt8195

    - Update to version 20241029 (git commit 048795eef350):
      * ath11k: move WCN6750 firmware to the device-specific subdir
      * xe: Update LNL GSC to v104.0.0.1263
      * i915: Update MTL/ARL GSC to v102.1.15.1926

    - Update to version 20241028 (git commit 987607d681cb):
      * amdgpu: DMCUB updates for various AMDGPU ASICs
      * i915: Add Xe3LPD DMC
      * cnm: update chips&media wave521c firmware.
      * linux-firmware: Add firmware for Cirrus CS35L41
      * linux-firmware: Update firmware file for Intel BlazarU core
      * Makefile: error out of 'install' if COPYOPTS is set

    - Update to version 20241018 (git commit 2f0464118f40):
      * check_whence.py: skip some validation if git ls-files fails
      * qcom: Add Audio firmware for X1E80100 CRD/QCPs
      * amdgpu: DMCUB updates forvarious AMDGPU ASICs
      * brcm: replace NVRAM for Jetson TX1
      * rtlwifi: Update firmware for RTL8192FU to v7.3
      * make: separate installation and de-duplication targets
      * check_whence.py: check the permissions
      * Remove execute bit from firmware files
      * configure: remove unused file
      * rtl_nic: add firmware rtl8125d-1

    - Update to version 20241014 (git commit 99f9c7ed1f4a):
      * iwlwifi: add gl/Bz FW for core91-69 release
      * iwlwifi: update ty/So/Ma firmwares for core91-69 release
      * iwlwifi: update cc/Qu/QuZ firmwares for core91-69 release
      * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for a Lenovo Laptop
      * cirrus: cs35l56: Add firmware for Cirrus CS35L56 for some ASUS laptops
      * cirrus: cs35l56: Add firmware for Cirrus Amps for some HP laptops
      * linux-firmware: update firmware for en8811h 2.5G ethernet phy
      * QCA: Add Bluetooth firmwares for WCN785x with UART transport

    - Update to version 20241011 (git commit 808cba847c70):
      * mtk_wed: add firmware for mt7988 Wireless Ethernet Dispatcher
      * ath12k: WCN7850 hw2.0: update board-2.bin (bsc#1230596)
      * ath12k: QCN9274 hw2.0: add to WLAN.WBE.1.3.1-00162-QCAHKSWPL_SILICONZ-1
      * ath12k: QCN9274 hw2.0: add board-2.bin
      * copy-firmware.sh: rename variables in symlink hanlding
      * copy-firmware.sh: remove no longer reachable test -L
      * copy-firmware.sh: remove no longer reachable test -f
      * copy-firmware.sh: call ./check_whence.py before parsing the file
      * copy-firmware.sh: warn if the destination folder is not empty
      * copy-firmware.sh: add err() helper
      * copy-firmware.sh: fix indentation
      * copy-firmware.sh: reset and consistently handle destdir
      * Revert 'copy-firmware: Support additional compressor options'
      * copy-firmware.sh: flesh out and fix dedup-firmware.sh
      * Style update yaml files
      * editorconfig: add initial config file
      * check_whence.py: annotate replacement strings as raw
      * check_whence.py: LC_ALL=C sort -u the filelist
      * check_whence.py: ban link-to-a-link
      * check_whence.py: use consistent naming
      * Add a link from TAS2XXX1EB3.bin -> ti/tas2781/TAS2XXX1EB30.bin
      * tas2781: Upload dsp firmware for ASUS laptop 1EB30 & 1EB31
    - Drop obsoleted --ignore-duplicates option to copy-firmware.sh
    - Drop the ath12k workaround again

    - Update to version 20241010 (git commit d4e688aa74a0):
      * rtlwifi: Add firmware v39.0 for RTL8192DU
      * Revert 'ath12k: WCN7850 hw2.0: update board-2.bin'
        (replaced with a newer firmware in this package instead)
    - update aliases

    - Update to version 20241004 (git commit bbb77872a8a7):
      * amdgpu: DMCUB DCN35 update
      * brcm: Add BCM4354 NVRAM for Jetson TX1
      * brcm: Link FriendlyElec NanoPi M4 to AP6356S nvram

    - Update to version 20241001 (git commit 51e5af813eaf):
      * linux-firmware: add firmware for MediaTek Bluetooth chip (MT7920)
      * linux-firmware: add firmware for MT7920
      * amdgpu: update raven firmware
      * amdgpu: update SMU 13.0.10 firmware
      * amdgpu: update PSP 13.0.10 firmware
      * amdgpu: update GC 11.0.3 firmware
      * amdgpu: update VCN 3.1.2 firmware
      * amdgpu: update PSP 13.0.5 firmware
      * amdgpu: update PSP 13.0.8 firmware
      * amdgpu: update vega12 firmware
      * amdgpu: update PSP 14.0.4 firmware
      * amdgpu: update GC 11.5.2 firmware
      * amdgpu: update vega10 firmware
      * amdgpu: update VCN 4.0.0 firmware
      * amdgpu: update PSP 13.0.0 firmware
      * amdgpu: update GC 11.0.0 firmware
      * amdgpu: update picasso firmware
      * amdgpu: update beige goby firmware
      * amdgpu: update vangogh firmware
      * amdgpu: update dimgrey cavefish firmware
      * amdgpu: update navy flounder firmware
      * amdgpu: update green sardine firmware
      * amdgpu: update VCN 4.0.2 firmware
      * amdgpu: update PSP 13.0.4 firmware
      * amdgpu: update GC 11.0.1 firmware
      * amdgpu: update sienna cichlid firmware
      * amdgpu: update VCN 4.0.6 firmware
      * amdgpu: update PSP 14.0.1 firmware
      * amdgpu: update GC 11.5.1 firmware
      * amdgpu: update VCN 4.0.5 firmware
      * amdgpu: update PSP 14.0.0 firmware
      * amdgpu: update GC 11.5.0 firmware
      * amdgpu: update navi14 firmware
      * amdgpu: update renoir firmware
      * amdgpu: update navi12 firmware
      * amdgpu: update SMU 13.0.6 firmware
      * amdgpu: update SDMA 4.4.2 firmware
      * amdgpu: update PSP 13.0.6 firmware
      * amdgpu: update GC 9.4.3 firmware
      * amdgpu: update yellow carp firmware
      * amdgpu: update VCN 4.0.4 firmware
      * amdgpu: update PSP 13.0.7 firmware
      * amdgpu: update GC 11.0.2 firmware
      * amdgpu: update navi10 firmware
      * amdgpu: update aldebaran firmware
      * qcom: update gpu firmwares for qcm6490 chipset
      * mt76: mt7996: add firmware files for mt7992 chipset
      * mt76: mt7996: add firmware files for mt7996 chipset variants
      * qcom: add gpu firmwares for sa8775p chipset
      * rtw89: 8922a: add fw format-2 v0.35.42.1
    - Pick up the fixed ath12k firmware from
      https://git.codelinaro.org/clo/ath-firmware/ath12k-firmware
      (bsc#1230596)
    - Update aliases from 6.11.x and 6.12-rc1

    - Update to version 20240913 (git commit bcbdd1670bc3):
      * amdgpu: update DMCUB to v0.0.233.0 DCN351
      * copy-firmware: Handle links to uncompressed files
      * WHENCE: Fix battmgr.jsn entry type
    - Temporary revert for ath12k firmware (bsc#1230596)

    - Update to version 20240912 (git commit 47c72fee8fe3):
      * amdgpu: Add VPE 6.1.3 microcode
      * amdgpu: add SDMA 6.1.2 microcode
      * amdgpu: Add support for PSP 14.0.4
      * amdgpu: add GC 11.5.2 microcode
      * qcom: qcm6490: add ADSP and CDSP firmware
      * linux-firmware: Update firmware file for Intel Bluetooth Magnetor core
      * linux-firmware: Update firmware file for Intel BlazarU core
      * linux-firmware: Update firmware file for Intel Bluetooth Solar core

    - Update to version 20240911 (git commit 59def907425d):
      * rtl_bt: Update RTL8852B BT USB FW to 0x0447_9301 (bsc#1229272)

    - Update to version 20240910 (git commit 2a7b69a3fa30):
      * realtek: rt1320: Add patch firmware of MCU
      * i915: Update MTL DMC v2.23
      * cirrus: cs35l56: Add firmware for Cirrus CS35L54 for some HP laptops

    - Update to version 20240903 (git commit 96af55bd3d0b):
      * amdgpu: Revert sienna cichlid dmcub firmware update (bsc#1230007)
      * iwlwifi: add Bz FW for core89-58 release
      * rtl_nic: add firmware rtl8126a-3
      * linux-firmware: update firmware for MT7921 WiFi device
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7921)

    - Update to version 20240830 (git commit d6c600d46981):
      * amdgpu: update DMCUB to v0.0.232.0 for DCN314 and DCN351
      * qcom: vpu: restore compatibility with kernels before 6.6

    - Update to version 20240826 (git commit bec4fd18cc57):
      (including ath11k f/w updates for bsc#1234027)
      * amdgpu: DMCUB updates forvarious AMDGPU ASICs
      * rtw89: 8922a: add fw format-1 v0.35.41.0
      * linux-firmware: update firmware for MT7925 WiFi device
      * linux-firmware: update firmware for mediatek bluetooth chip (MT7925)
      * rtl_bt: Add firmware and config files for RTL8922A
      * rtl_bt: Add firmware file for the the RTL8723CS Bluetooth part
      * rtl_bt: de-dupe identical config.bin files
      * rename rtl8723bs_config-OBDA8723.bin -> rtl_bt/rtl8723bs_config.bin
      * linux-firmware: Update AMD SEV firmware
      * linux-firmware: update firmware for MT7996
      * Revert 'i915: Update MTL DMC v2.22'
      * ath12k: WCN7850 hw2.0: update board-2.bin
      * ath11k: WCN6855 hw2.0: update to WLAN.HSP.1.1-03125-QCAHSPSWPL_V1_V2_SILICONZ_LITE-3.6510.41
      * ath11k: WCN6855 hw2.0: update board-2.bin
      * ath11k: QCA2066 hw2.1: add to WLAN.HSP.1.1-03926.13-QCAHSPSWPL_V2_SILICONZ_CE-2.52297.3
      * ath11k: QCA2066 hw2.1: add board-2.bin
      * ath11k: IPQ5018 hw1.0: update to WLAN.HK.2.6.0.1-01291-QCAHKSWPL_SILICONZ-1
      * qcom: vpu: add video firmware for sa8775p
      * amdgpu: DMCUB updates for various AMDGPU ASICs

    - Update to version 20240809 (git commit 36db650dae03):
      * qcom: update path for video firmware for vpu-1/2/3.0
      * QCA: Update Bluetooth WCN685x 2.1 firmware to 2.1.0-00642
      * rtw89: 8852c: add fw format-1 v0.27.97.0
      * rtw89: 8852bt: add firmware 0.29.91.0
      * amdgpu: Update ISP FW for isp v4.1.1
      * mediatek: Update mt8195 SOF firmware
      * amdgpu: DMCUB updates for DCN314
      * xe: First GuC release v70.29.2 for BMG
      * xe: Add GuC v70.29.2 for LNL
      * i915: Add GuC v70.29.2 for ADL-P, DG1, DG2, MTL, and TGL
      * i915: Update MTL DMC v2.22
      * i915: update MTL GSC to v102.0.10.1878
      * xe: Add BMG HuC 8.2.10
      * xe: Add GSC 104.0.0.1161 for LNL
      * xe: Add LNL HuC 9.4.13
      * i915: update DG2 HuC to v7.10.16
      * amdgpu: Update ISP FW for isp v4.1.1
      * QCA: Update Bluetooth QCA2066 firmware to 2.1.0-00641

    - Issues already fixed in past releases:
      * CVE-2023-31315: Fixed improper validation in a model specific register (MSR) could allow a malicious
                        program with ring0 access to modify SMM configuration (bsc#1229069)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234027");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/019965.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fe22a83");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-31315");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-31315");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-amdgpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath10k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath11k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ath12k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-atheros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-bnx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-brcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-chelsio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-dpaa2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-i915");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-iwlwifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-liquidio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-media");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mediatek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mellanox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-mwifiex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nfp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-prestera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-qcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-qlogic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-radeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-realtek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-ueagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-firmware-usb-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ucode-amd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-firmware-all-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-all-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-atheros-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-atheros-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-brcm-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-brcm-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-i915-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-i915-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-intel-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-intel-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-marvell-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-marvell-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-media-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-media-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nfp-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nfp-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-platform-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-platform-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-prestera-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-prestera-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qcom-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qcom-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-radeon-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-radeon-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-realtek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-realtek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-serial-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-serial-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-sound-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-sound-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ti-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ti-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'ucode-amd-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'ucode-amd-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-firmware-all-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-all-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-atheros-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-atheros-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-brcm-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-brcm-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-i915-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-i915-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-intel-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-intel-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-marvell-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-marvell-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-media-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-media-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nfp-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nfp-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-platform-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-platform-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-prestera-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-prestera-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qcom-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qcom-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-radeon-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-radeon-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-realtek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-realtek-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-serial-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-serial-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-sound-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-sound-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ti-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ti-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'ucode-amd-20241128-150600.3.9.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'ucode-amd-20241128-150600.3.9.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-firmware-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-all-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-amdgpu-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath10k-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath11k-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ath12k-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-atheros-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-bluetooth-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-bnx2-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-brcm-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-chelsio-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-dpaa2-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-i915-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-intel-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-iwlwifi-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-liquidio-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-marvell-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-media-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mediatek-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mellanox-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-mwifiex-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-network-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nfp-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-nvidia-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-platform-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-prestera-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-qcom-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-qlogic-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-radeon-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-realtek-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-serial-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-sound-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ti-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-ueagle-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-firmware-usb-network-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ucode-amd-20241128-150600.3.9.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-firmware / kernel-firmware-all / kernel-firmware-amdgpu / etc');
}
