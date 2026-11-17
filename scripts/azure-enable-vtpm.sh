#!/usr/bin/env bash
# Enable a vTPM on an existing Azure Gen2 VM (Trusted Launch, Secure Boot kept OFF) — one VM per run.
#
#   scripts/azure-enable-vtpm.sh <vm-name> [-g <resource-group>] [--check-only] [--no-snapshot] [--yes] [--ssh user@host]
#
# Runs in the operator's terminal with an `az login` into the subscription that holds the VM.
# Every step prints what it is about to do and waits for Enter (Ctrl-C aborts; nothing runs
# half-way: each step is one az call). `--yes` skips the prompts; `--check-only` stops after the
# read-only step 1 (run it any time before the window). Everything is logged to
# ./azure-enable-vtpm-<vm>-<stamp>.log — paste its tail into the tracking issue.
#
# What happens, step by step (issue #1 of github.com/77ph/BTCPayTEE, option A):
#   0  show the subscription and the VM (size, image, security type, OS disk, public IP) — read-only
#   1  read-only checks: not already Trusted Launch; the size does not carry TrustedLaunchDisabled;
#      the OS disk is Hyper-V generation V2; every public IP is Static; no Azure Backup on the VM
#   2  snapshot of the OS disk (the restore point Microsoft recommends; skip with --no-snapshot)
#   3  az vm deallocate                                   <- downtime begins for every tenant of the VM
#   4  az vm update --security-type TrustedLaunch --enable-vtpm true --enable-secure-boot false
#      if Azure refuses: nothing has changed; the script starts the VM again and exits 1
#   5  az vm start                                        <- downtime ends
#   6  show the result; with --ssh, read-only checks inside the guest (/dev/tpmrm0, TPM 2.0, SGX
#      devices, docker ps); without --ssh the same commands are printed to run by hand
#
# Secure Boot stays off on purpose: nothing in the stacks needs it, and it is the one component that
# can keep a VM from booting (unsigned kernel modules). It can be enabled later by a separate update.
# Trusted Launch does not change the VM price. Rolling back to Standard is a one-way door (Microsoft:
# Trusted Launch cannot be re-enabled on that VM afterwards); the snapshot is the way back if the VM
# does not boot. Disks and data are untouched by every step.
set -euo pipefail

usage() { sed -n '2,9p' "$0"; exit "${1:-0}"; }

VM=""; RG="SGX-RG"; SNAPSHOT=1; YES=0; SSH_TARGET=""; CHECK_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -g|--resource-group) RG="$2"; shift 2 ;;
    --no-snapshot) SNAPSHOT=0; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --ssh) SSH_TARGET="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 1 ;;
    *) [ -z "$VM" ] || { echo "one VM per run" >&2; usage 1; }; VM="$1"; shift ;;
  esac
done
[ -n "$VM" ] || usage 1
command -v az >/dev/null || { echo "az (Azure CLI) not found" >&2; exit 1; }

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG="./azure-enable-vtpm-${VM}-${STAMP}.log"
exec > >(tee -a "$LOG") 2>&1
echo "# azure-enable-vtpm.sh  vm=$VM  rg=$RG  snapshot=$SNAPSHOT  utc=$STAMP  log=$LOG"

step() { echo; echo "== step $1: $2"; }
confirm() {
  [ "$YES" = 1 ] && return 0
  read -r -p ">> Enter to run this step, Ctrl-C to abort: " _ </dev/tty
}
fail() { echo "!! $*" >&2; exit 1; }
vmq() { az vm show -g "$RG" -n "$VM" --query "$1" -o tsv; }

# ---------------------------------------------------------------- 0 ------------------------------
step 0 "subscription and VM (read-only)"
az account show --query "{subscription:name, id:id, user:user.name}" -o table
az vm show -g "$RG" -n "$VM" >/dev/null || fail "VM $VM not found in resource group $RG (check 'az account show' and -g)"
az vm show -g "$RG" -n "$VM" -d --query "{name:name, location:location, size:hardwareProfile.vmSize, image:storageProfile.imageReference.sku, osType:storageProfile.osDisk.osType, osDisk:storageProfile.osDisk.name, securityType:securityProfile.securityType, vtpm:securityProfile.uefiSettings.vTpmEnabled, secureBoot:securityProfile.uefiSettings.secureBootEnabled, power:powerState, publicIps:publicIps}" -o json
LOCATION=$(vmq location); SIZE=$(vmq hardwareProfile.vmSize)
OS_DISK_ID=$(vmq storageProfile.osDisk.managedDisk.id); OS_DISK=$(vmq storageProfile.osDisk.name)
SEC_TYPE=$(vmq 'securityProfile.securityType || `Standard`')
echo "   this is the VM every tenant of which goes down in step 3. Is it the right one?"
confirm

# ---------------------------------------------------------------- 1 ------------------------------
step 1 "read-only checks"
if [ "$SEC_TYPE" = "TrustedLaunch" ]; then
  VTPM=$(vmq securityProfile.uefiSettings.vTpmEnabled)
  echo "   security type is already TrustedLaunch, vTPM enabled: $VTPM"
  [ "$VTPM" = "true" ] && { echo "   nothing to do"; exit 0; }
  echo "   vTPM is off on a Trusted Launch VM: steps 3-5 below will turn it on (same az vm update)"
elif [ "$SEC_TYPE" != "Standard" ]; then
  fail "security type is $SEC_TYPE — this script only converts Standard (or TL without vTPM); a ConfidentialVM is out of scope"
fi

echo "   size capability TrustedLaunchDisabled (may take a minute; empty = allowed, True = Azure will refuse step 4):"
TL_DISABLED=$(az vm list-skus --location "$LOCATION" --size "$SIZE" \
  --query "[?name=='$SIZE'].capabilities[?name=='TrustedLaunchDisabled'].value | [0][0]" -o tsv)
echo "   $SIZE: TrustedLaunchDisabled=[${TL_DISABLED:-absent}]"
[ "${TL_DISABLED}" != "True" ] || fail "the size refuses Trusted Launch — option A is closed for this VM (issue #1 §3.3)"

HV_GEN=$(az disk show --ids "$OS_DISK_ID" --query hyperVGeneration -o tsv)
DISK_GB=$(az disk show --ids "$OS_DISK_ID" --query diskSizeGB -o tsv)
echo "   OS disk $OS_DISK: hyperVGeneration=$HV_GEN size=${DISK_GB}GiB"
[ "$HV_GEN" = "V2" ] || fail "Trusted Launch needs a Generation 2 VM; this OS disk is $HV_GEN"

echo "   public IPs (must be Static — a Dynamic one changes on deallocation):"
DYNAMIC=0
while IFS=$'\t' read -r IP NAME; do
  [ -n "$IP" ] || continue
  ALLOC=$(az network public-ip list --query "[?ipAddress=='$IP'].publicIPAllocationMethod | [0]" -o tsv)
  echo "   $NAME $IP $ALLOC"
  [ "$ALLOC" = "Static" ] || DYNAMIC=1
done < <(az vm list-ip-addresses -g "$RG" -n "$VM" --query "[].virtualMachine.network.publicIpAddresses[].[ipAddress, name]" -o tsv)
[ "$DYNAMIC" = 0 ] || fail "a public IP is not Static. Make it static first, no downtime: az network public-ip update -g $RG -n <ip-name> --allocation-method Static"

VM_ID=$(vmq id)
BACKUP_ERR=$(mktemp)
if BACKUP=$(az backup protection check-vm --vm "$VM_ID" -o tsv 2>"$BACKUP_ERR"); then
  echo "   Azure Backup: ${BACKUP:-none}"
  [ -z "$BACKUP" ] || fail "the VM is protected by Azure Backup ($BACKUP); a Standard backup policy blocks Trusted Launch — remove or switch it first"
  echo "   (Azure Site Recovery must also be off for this VM — check the Recovery Services vaults of the subscription)"
elif grep -q ProviderNotRegistered "$BACKUP_ERR"; then
  echo "   Azure Backup / Site Recovery: none possible — Microsoft.RecoveryServices is not registered in this subscription"
else
  cat "$BACKUP_ERR"; rm -f "$BACKUP_ERR"; fail "could not check Azure Backup (error above)"
fi
rm -f "$BACKUP_ERR"
echo "   checks passed"
[ "$CHECK_ONLY" = 0 ] || { echo "   --check-only: stopping here (nothing changed)"; exit 0; }

# ---------------------------------------------------------------- 2 ------------------------------
SNAP_NAME="${VM}-os-pre-vtpm-$(date -u +%Y-%m-%d)"
if [ "$SNAPSHOT" = 1 ]; then
  step 2 "snapshot of the OS disk -> $SNAP_NAME (no downtime; the disk is not modified)"
  confirm
  az snapshot create -g "$RG" -n "$SNAP_NAME" --source "$OS_DISK_ID" \
    --query "{name:name, state:provisioningState, sizeGb:diskSizeGB, sku:sku.name}" -o table
  [ "$(az snapshot show -g "$RG" -n "$SNAP_NAME" --query provisioningState -o tsv)" = "Succeeded" ] || fail "snapshot not Succeeded"
  echo "   delete it once the VM is confirmed good: az snapshot delete -g $RG -n $SNAP_NAME"
else
  step 2 "snapshot SKIPPED (--no-snapshot)"
fi

# ---------------------------------------------------------------- 3 ------------------------------
step 3 "deallocate $VM — DOWNTIME BEGINS for every service on this VM"
confirm
az vm deallocate -g "$RG" -n "$VM"
POWER=$(az vm show -g "$RG" -n "$VM" -d --query powerState -o tsv)
echo "   power state: $POWER"
[ "$POWER" = "VM deallocated" ] || fail "expected 'VM deallocated'"

# ---------------------------------------------------------------- 4 ------------------------------
step 4 "az vm update --security-type TrustedLaunch --enable-vtpm true --enable-secure-boot false"
confirm
if az vm update -g "$RG" -n "$VM" --security-type TrustedLaunch --enable-vtpm true --enable-secure-boot false \
     --query "securityProfile" -o json; then
  echo "   update accepted"
else
  echo "!! Azure refused the update — the VM is unchanged (still Standard). Starting it again."
  az vm start -g "$RG" -n "$VM"
  az vm show -g "$RG" -n "$VM" -d --query "{power:powerState, publicIps:publicIps, securityType:securityProfile.securityType}" -o table
  fail "option A is closed for $VM; see the error above and issue #1 §3.3 / option B"
fi

# ---------------------------------------------------------------- 5 ------------------------------
step 5 "start $VM — downtime ends when the guest is up"
confirm
az vm start -g "$RG" -n "$VM"
az vm show -g "$RG" -n "$VM" -d --query "{power:powerState, publicIps:publicIps, securityType:securityProfile.securityType, vtpm:securityProfile.uefiSettings.vTpmEnabled, secureBoot:securityProfile.uefiSettings.secureBootEnabled}" -o table
[ "$(vmq securityProfile.uefiSettings.vTpmEnabled)" = "true" ] || fail "vTpmEnabled is not true after the update"

# ---------------------------------------------------------------- 6 ------------------------------
step 6 "inside the guest (read-only)"
GUEST_CHECK='echo "-- $(hostname) $(uname -r)"; ls -l /dev/tpm0 /dev/tpmrm0 2>&1; echo "tpm major version: $(cat /sys/class/tpm/tpm0/tpm_version_major 2>&1)"; ls -l /dev/sgx_enclave /dev/sgx_provision 2>&1; docker ps --format "{{.Names}}  {{.Status}}" 2>&1'
if [ -n "$SSH_TARGET" ]; then
  echo "   waiting for ssh to $SSH_TARGET"
  for i in $(seq 1 30); do
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH_TARGET" true 2>/dev/null && break
    sleep 10
    [ "$i" -lt 30 ] || fail "no ssh after 5 minutes — look at: az vm boot-diagnostics get-boot-log -g $RG -n $VM"
  done
  ssh -o BatchMode=yes "$SSH_TARGET" "$GUEST_CHECK"
else
  echo "   run on the VM:"
  echo "   $GUEST_CHECK"
fi
echo
echo "== done. Expected inside the guest: /dev/tpm0 and /dev/tpmrm0 present, tpm major version 2, the SGX devices"
echo "   unchanged, every 'unless-stopped' container back. Each tenant brings up what is not auto-started."
echo "   If the VM does not boot: az vm boot-diagnostics get-boot-log -g $RG -n $VM; the way back is the snapshot"
echo "   ($SNAP_NAME): create a disk from it and swap the OS disk. Rolling the security type back to Standard"
echo "   (az vm update --security-type Standard, deallocated) is ONE-WAY: Trusted Launch cannot be re-enabled."
echo "   log: $LOG"
