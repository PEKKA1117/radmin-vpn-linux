# Wine gap: four missing perflib V2 exports

This is the upstream note for the workaround in `src/adapter_hook.c`
(`perf_fill_in`). It documents a Wine gap, not a Radmin bug — the day Wine ships
the four exports, the workaround becomes dead code.

## The gap

Wine's `advapi32` implements the perflib V2 provider API but exports only part of
it. Measured on Wine 11.13 Staging:

```
$ winedump -j export /usr/lib/wine/i386-windows/advapi32.dll | grep -i perf
  00018A50   363  PerfAddCounters
  00018AD0   364  PerfCloseQueryHandle
  00005F08   365  PerfCreateInstance
  00005F1C   366  PerfDeleteInstance
  00018B20   367  PerfOpenQueryHandle
  00018BA0   368  PerfQueryCounterData
  00005F30   369  PerfSetCounterRefValue
  00005F44   370  PerfSetCounterSetInfo
  00005F58   371  PerfSetULongCounterValue
  00005F6C   372  PerfSetULongLongCounterValue
  00005F80   373  PerfStartProvider
  00005F94   374  PerfStartProviderEx
  00005FA8   375  PerfStopProvider
```

Absent, though documented since Windows Vista and part of the same API family:

- `PerfIncrementULongCounterValue`
- `PerfIncrementULongLongCounterValue`
- `PerfDecrementULongCounterValue`
- `PerfDecrementULongLongCounterValue`

## Why it is not cosmetic

Radmin VPN 2.1 wraps the API in a `FamRT::CPerfCounterset` class that resolves
seven entry points in one cascade (`RvControlSvc.exe+0x82800`, base 0x400000) and
returns failure if **any single one** is unresolved. So four missing names abort
the counterset before `PerfCreateInstance` is ever called — even though Wine's
`PerfCreateInstance` works correctly once reached.

The service then stores the resulting `NULL` per-peer counter object in
`node+0xdc` and passes it as the payload of the outgoing peer handshake
(`+0x423980` → `+0x41c300`, which bails on a NULL payload without recording a
reason). The visible result is that the service reaches ONLINE and joins networks
normally, while every peer connection fails with `error: 0x700000000` — a generic
give-up code that carries no diagnostic information.

In other words: a missing performance counter takes down the entire peer data
path, and the error surfaced gives no hint of it.

## Suggested upstream fix

Add the four functions to `dlls/advapi32/advapi32.spec` and implement them in
`dlls/advapi32/perf.c` alongside the existing `PerfSetULongCounterValue` /
`PerfSetULongLongCounterValue`. Signatures (all `WINAPI`, returning a Win32
error code):

```c
ULONG PerfIncrementULongCounterValue    (HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG);
ULONG PerfIncrementULongLongCounterValue(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG);
ULONG PerfDecrementULongCounterValue    (HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONG);
ULONG PerfDecrementULongLongCounterValue(HANDLE, PPERF_COUNTERSET_INSTANCE, ULONG, ULONGLONG);
```

Each is a read-modify-write on the counter the corresponding `PerfSet*` already
locates, so the existing counter lookup can be reused directly.

## The workaround here

`hook_GetProcAddress` in `src/adapter_hook.c` answers those four names — and only
those four, and only when Wine itself returns NULL — with no-op stubs returning
`ERROR_SUCCESS`. The counters then read zero, which nothing on the data path
consumes; only the existence of the counterset object matters.

Note the two stubs are not interchangeable: the `ULongLong` variants take a
64-bit value and therefore pop 20 bytes instead of 16. Both are `__stdcall` with
four arguments, verified against the call sites at `RvControlSvc.exe+0x4826a6`
and `+0x4824c9`.
