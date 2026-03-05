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
I recently started exploring kernel-mode drivers for Bring Your Own Vulnerable Driver (BYOVD) attacks when conducting network testing. I found that many data forensics tools often export functions that can be leveraged for exploitation, like `ZwOpenSection`, `MmMapIoSpace`, & `ZwTerminateProcess`. A particular driver I found was using `IoBuildSynchronousFsdRequest` and `IofCallDriver` to read files from disk.sys bypassing NTFS protections. Unfortunately, the driver is not cross-signed by Microsoft, mitigating a lot of the impact. *I will update this post with the name of the driver once it is properly disclosed to the vendor*
