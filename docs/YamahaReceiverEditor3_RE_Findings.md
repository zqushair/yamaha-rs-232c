# Yamaha Receiver Editor 3 — RS-232C Reverse Engineering Findings

This document wraps up the current reverse-engineering findings for `YamahaReceiverEditor3.exe`. It does **not** include any additional analysis beyond what was already observed.

## Target

| Field | Value |
|---|---|
| File | `YamahaReceiverEditor3.exe` (third-party Windows application, not included in this repository) |
| SHA256 | `371a84b1d9c92099b9a452333a11d5f853ad778a39ffe7a4a5057636ab779b2e` |
| Type | Windows PE executable |

## Analysis Artifacts

The following offline analysis artifacts were generated during this work and are not included in this repository:

| Artifact | Purpose |
|---|---|
| `full_disasm.txt` | Main offline Intel-syntax disassembly generated with `objdump -d -M intel`. |
| `yamaha_command_table.csv` | Extracted command dictionary for ordinary IDs `0x00..0x6c`, including handler mapping, frame type, record count, and ASCII records. |
| `ymah_strings.txt` | String dump containing UI, serial, and protocol/debug strings. |

## Executive Summary

The application builds Yamaha AV receiver RS-232C command frames using a central builder function `sub_42a430`, then sends them through a serial write wrapper `sub_418df0`.

The strongest current model is:

```text
STX + ASCII command record bytes [+ optional formatted value/checksum chars] + ETX
```

Two broad frame shapes were identified:

1. **Full record selection**
   ```text
   02 <5 ASCII record chars> 03
   ```

2. **Record prefix + formatted two-character field**
   ```text
   02 <3 ASCII record chars><2 formatted ASCII chars> 03
   ```

The application also contains a special builder path for ID `0xff` that produces a short non-record frame:

```text
11 30 30 30 03
```

or, as bytes:

```text
0x11 '0' '0' '0' 0x03
```

## Command Builder

### Function

| Item | Value |
|---|---|
| Builder function | `sub_42a430` |
| Address | `0x42a430` |
| Disassembly line | around `51023` in `full_disasm.txt` |
| Approximate signature | `builder(this, id, value)` |

### Pseudocode (Hopper Decompilation)

```c
void* builder(void* this, int id, int value) {
    void* edi = this + 0x1e;
    
    if (id > 0x6c) {
        if (id != 0xff) {
            // Invalid ID path
            sub_406d30();    // CString cleanup
            sub_4471d7();    // cleanup
            return (void*)0x46df20;  // static error string
        }
        // id == 0xff: special frame
        edi[0] = 0x11;
        edi[1] = 0x30;  // '0'
        edi[2] = 0x30;  // '0'
        edi[3] = 0x30;  // '0'
        edi[4] = 0x03;  // ETX
        edi[5] = 0x00;  // NUL
        sub_406d30();
        sub_4471d7();
        return edi;
    }
    
    // id <= 0x6c
    edi[0] = 0x02;  // STX
    
    int ecx = id - 0x30;
    if ((unsigned)ecx <= 0x3c) {  // id in [0x30, 0x6c]
        // Dispatch through byte table + pointer table
        handler = *(int*)(byte_table[ecx] * 4 + 0x42a640);
        handler(this, id, value);
    } else {
        // id < 0x30 (unsigned wrap-around): use h_full_record directly
        h_full_record(this, id, value);
    }
    
    // Epilogue: write ETX + NUL, cleanup
    this[0x24] = 0x03;  // ETX
    this[0x25] = 0x00;  // NUL
    sub_406d30();
    sub_4471d7();
    return edi;
}
```

### Observed Behavior

- Builder object/state is referenced globally around `0x46f3a8`.
- The builder writes an outgoing frame into the object buffer starting at:

  ```text
  this + 0x1e
  ```

- Ordinary command IDs are observed constrained to:

  ```text
  id <= 0x6c
  ```

- Special case:

  ```text
  id == 0xff
  ```

  writes a fixed sequence:

  | Offset | Value | Meaning |
  |---|---:|---|
  | `this+0x1e` | `0x11` | observed special marker byte |
  | `this+0x1f` | `'0'` / `0x30` | ASCII zero |
  | `this+0x20` | `'0'` / `0x30` | ASCII zero |
  | `this+0x21` | `'0'` / `0x30` | ASCII zero |
  | `this+0x22` | `0x03` | ETX |
  | `this+0x23` | `0x00` | NUL terminator for sender string handling |

- Invalid ID paths call CString cleanup helpers and reference static pointer `0x46df20`; the exact error semantics were not fully resolved.

## Command Lookup

### Function

| Item | Value |
|---|---|
| Lookup function | `sub_42aaa0` |
| Address | `0x42aaa0` |
| Disassembly line | around `51554` |
| Approximate signature | `record = lookup(id, value)` |

### Mechanism

The lookup uses a master pointer table and fixed-size records.

```text
master_table[id] + value * 5
```

Confirmed constants:

| Item | Value |
|---|---|
| Master pointer table | `0x469b9c` |
| Record stride | `5` bytes |
| Ordinary extracted ID range | `0x00..0x6c` |
| Persisted extraction output | `yamaha_command_table.csv` |

The record pool is contiguous/overlapping. Early IDs differ by 12-byte base offsets, for example:

```text
ID 0x00 -> 0x4589e0
ID 0x01 -> 0x4589ec
ID 0x02 -> 0x4589f8
```

## Handler Dispatch

### Dispatch Mechanism

The builder dispatches by ID through a two-level table:

1. **Byte table** at `0x42a64c` (61 bytes, indices `0x00..0x3c`): maps `id - 0x30` to a handler index (0, 1, or 2)
2. **Pointer table** at `0x42a640` (3 entries, 4 bytes each): maps handler index to handler address

```asm
mov    ecx, eax
sub    ecx, 0x30           ; ecx = id - 0x30
cmp    ecx, 0x3c
ja     0x42a5e5            ; unsigned > 0x3c → h_full_record (covers id < 0x30)
xor    edx, edx
mov    dl, [ecx+0x42a64c]  ; byte table lookup
jmp    [edx*4+0x42a640]    ; pointer table dispatch
```

### Handler Table

| Handler Index | Handler | Address | Description |
|---|---:|---|---|
| 0 | `h_prefix_plus_value_a` | `0x42a4fd` | Copies 3 record bytes + formats 2 hex chars with `+0x26` adjustment for nonzero values |
| 1 | `h_prefix_plus_value_b` | `0x42a589` | Copies 3 record bytes + formats 2 hex chars directly (no adjustment) |
| 2 | `h_full_record` | `0x42a5e5` | Copies all 5 record bytes; value selects which record |

### Dispatch Table Contents

**Byte table at `0x42a64c` (61 bytes):**

| ID Range | Byte Value | Handler |
|---|---|---|
| `0x00..0x2f` | (unsigned wrap) | `0x42a5e5` (h_full_record) |
| `0x30, 0x31, 0x34` | `0x00` | `0x42a4fd` (h_prefix_plus_value_a) |
| `0x32, 0x36..0x45, 0x48, 0x49` | `0x01` | `0x42a589` (h_prefix_plus_value_b) |
| `0x33, 0x35, 0x46, 0x47, 0x4a..0x6c` | `0x02` | `0x42a5e5` (h_full_record) |

**Pointer table at `0x42a640`:**

| Index | Address | Handler |
|---:|---|---|
| 0 | `0x0042a4fd` | h_prefix_plus_value_a |
| 1 | `0x0042a589` | h_prefix_plus_value_b |
| 2 | `0x0042a5e5` | h_full_record |

## Handler Details

### Handler `0x42a4fd` — h_prefix_plus_value_a

**Used by IDs:** `0x30`, `0x31`, `0x34`

**Frame shape:**
```text
STX + 3 ASCII record chars + 2 formatted hex chars + ETX
```

**Complete behavior (from disassembly):**

1. Calls `sub_42aaa0(this, id, 0)` — looks up record with **value=0** (not the actual value)
2. Copies first 3 bytes of record to frame offsets `+0x1f`, `+0x20`, `+0x21`
3. If `value == 0`:
   - Calls `sub_407060(&temp, 0)` — formats 0 as two hex chars
4. If `value != 0`:
   - Calls `sub_407060(&temp, value + 0x26)` — formats **value + 0x26** as two hex chars
5. Copies the two formatted chars to frame offsets `+0x22` and `+0x23`
6. Jumps to common epilogue (writes ETX + NUL, cleanup)

**Key observation:** The record lookup always uses `value=0`, so the record prefix is fixed for a given ID. The actual value only affects the two formatted hex characters.

**Protocol meaning of `+0x26`:** The adjustment `0x26` (decimal 38) maps:
- `value=0` → hex `00`
- `value=1` → hex `27` (0x01 + 0x26 = 0x27)
- `value=2` → hex `28` (0x02 + 0x26 = 0x28)
- etc.

This appears to be a command-family-specific offset, possibly mapping a small integer to a printable ASCII range or a Yamaha-specific encoding.

### Handler `0x42a589` — h_prefix_plus_value_b

**Used by IDs:** `0x32`, `0x36..0x45`, `0x48`, `0x49`

**Frame shape:**
```text
STX + 3 ASCII record chars + 2 formatted hex chars + ETX
```

**Complete behavior (from disassembly):**

1. Calls `sub_42aaa0(this, id, 0)` — looks up record with **value=0**
2. Copies first 3 bytes of record to frame offsets `+0x1f`, `+0x20`, `+0x21`
3. Calls `sub_407060(&temp, value)` — formats value **directly** as two hex chars (NO `+0x26` adjustment)
4. Copies the two formatted chars to frame offsets `+0x22` and `+0x23`
5. Jumps to common epilogue

**Key difference from handler A:** No `+0x26` adjustment. The value is formatted as-is.

### Handler `0x42a5e5` — h_full_record

**Used by IDs:** `0x00..0x2f`, `0x33`, `0x35`, `0x46`, `0x47`, `0x4a..0x6c`

**Frame shape:**
```text
STX + 5 ASCII record chars + ETX
```

**Complete behavior (from disassembly):**

1. Calls `sub_42aaa0(this, id, value)` — looks up record with **the actual value**
2. Copies all 5 bytes of record to frame offsets `+0x1f` through `+0x23`
3. Falls through to common epilogue

**Key difference:** The value selects which 5-byte record to use from the command table.

### Common Epilogue (at `0x42a603`)

```asm
mov    BYTE PTR [esi+0x24], 0x03   ; ETX
mov    BYTE PTR [esi+0x25], 0x00   ; NUL terminator
lea    ecx, [esp+0x14]
mov    BYTE PTR [esp+0x24], 0x00
call   0x406d30                      ; CString cleanup
lea    ecx, [esp+0x08]
mov    DWORD PTR [esp+0x24], 0xffffffff
call   0x4471d7                      ; CString cleanup
mov    ecx, [esp+0x1c]              ; restore stack cookie
mov    eax, edi                     ; return frame buffer pointer
pop    edi
pop    esi
mov    fs:0x0, ecx                  ; restore stack cookie
add    esp, 0x20
ret    0x8
```

## Frame Formats

### Format 1: Full Record

Used by handler `0x42a5e5` (IDs `0x00..0x2f`, `0x33`, `0x35`, `0x46`, `0x47`, `0x4a..0x6c`).

```text
offset +0x1e: STX (0x02)
offset +0x1f: record char 0
offset +0x20: record char 1
offset +0x21: record char 2
offset +0x22: record char 3
offset +0x23: record char 4
offset +0x24: ETX (0x03)
offset +0x25: NUL (0x00)
```

Wire shape:

```text
02 <5 ASCII chars> 03
```

In this style, the numeric `value` selects which 5-character command record to use.

Example patterns observed from extracted table:

```text
ID 0x00 value 0 -> record "07A1B"
ID 0x00 value 1 -> record "07A1A"
```

### Format 2: Prefix + Two Formatted Characters

Used by handlers `0x42a4fd` and `0x42a589`.

```text
offset +0x1e: STX (0x02)
offset +0x1f: record char 0
offset +0x20: record char 1
offset +0x21: record char 2
offset +0x22: formatted ASCII char 0
offset +0x23: formatted ASCII char 1
offset +0x24: ETX (0x03)
offset +0x25: NUL (0x00)
```

Wire shape:

```text
02 <3 ASCII chars><2 formatted ASCII chars> 03
```

The first three bytes come from the command record base (always looked up with value=0). The final two ASCII characters are produced by the value formatter.

## Value Formatter `sub_407060`

### Function

| Item | Value |
|---|---|
| Formatter wrapper | `sub_407060` |
| Address | `0x407060` |
| Core formatter | `sub_407075` |
| Address | `0x407075` |
| Approximate signature | `format_two_hex_chars(CString* dest, int value)` |

### Core Formatter Pseudocode (`sub_407075`)

```c
CString* format_two_hex_chars(CString* dest, int value, void* arg_c) {
    int ecx = value & 0x8000000f;    // low nibble with sign handling
    if (ecx < 0) {
        ecx = (ecx - 1 | 0xfffffff0) + 1;
    }
    int esi = SAR(value, 4);          // arithmetic shift right by 4 = high nibble
    
    if (esi >= 0x10) {
        // Fallback: use static string "00" at 0x4681ac
        sub_447245(0x4681ac);         // assign "00" to CString
        return arg_c;
    }
    
    // Convert nibbles to hex
    sub_436923(ecx, &var_4, 0x10);    // low nibble to hex
    sub_436923(esi, &arg_10, 0x10);   // high nibble to hex
    
    sub_447669(0x3);                  // GetBuffer(3)
    sub_4476ad(0x0, arg_10);          // SetAt(0, high_nibble_char)
    sub_4476ad(0x1, var_4);           // SetAt(1, low_nibble_char)
    sub_4476ad(0x2, 0x0);             // SetAt(2, NUL)
    sub_447641(0xffffffff);           // ReleaseBuffer(-1)
    sub_447689();                     // cleanup
    
    sub_446f4c(&var_C);               // CString assignment
    return arg_c;
}
```

### Strongly Supported Conclusion

`sub_407075` formats a byte-sized command value as **two uppercase hexadecimal ASCII characters**.

The value is treated as a signed 32-bit integer:
- Low nibble: `value & 0xf` (with sign handling for negative values)
- High nibble: `value >> 4` (arithmetic shift)
- If high nibble >= 0x10 (i.e., value > 0xFF or negative): fallback to "00"

### Evidence

Observed sequence includes:

1. High-nibble guard:

   ```asm
   if ((value >> 4) >= 0x10) assign static string at 0x4681ac
   ```

2. Static string dump at raw offset `0x681ac`:

   ```text
   30 30 00
   ```

   This confirms the invalid/high fallback string is `"00"`.

3. Two base-16 conversions using `sub_436923` (itoa wrapper):
   - one for the low nibble,
   - one for the high nibble.

4. CString construction sequence:
   - `GetBuffer(3)`
   - `SetAt(0, ...)`
   - `SetAt(1, ...)`
   - `SetAt(2, 0)`
   - `ReleaseBuffer(-1)`

5. Helper analysis confirmed:
   - `sub_4476ad` behaves like `CString::SetAt(index, char)`.
   - `sub_447669` behaves like `CString::GetBuffer(length)`.
   - `sub_447641` behaves like `CString::ReleaseBuffer(-1)` and uses string length.

## Handler Value Adjustment

### Handler `0x42a4fd` (h_prefix_plus_value_a)

Observed behavior:

- If the incoming value is zero:
  - call formatter directly.
- If the incoming value is nonzero:
  - add `0x26` before calling formatter.
- After formatting, copy two characters into the frame buffer at offsets corresponding to `+0x22` and `+0x23`.

Conceptually:

```c
if (value != 0) {
    value += 0x26;
}

format_two_hex_chars(&temp, value);
frame[+0x22] = temp[0];
frame[+0x23] = temp[1];
```

The exact protocol meaning of the `+0x26` adjustment was not fully decoded. It may be a command-family-specific offset or printable-range adjustment.

### Handler `0x42a589` (h_prefix_plus_value_b)

Observed behavior:

- Calls `sub_42aaa0(this, id, 0)` — record lookup with value=0
- Copies first 3 record bytes to frame
- Calls `sub_407060(&temp, value)` — formats value **directly** (no adjustment)
- Copies formatted chars to frame offsets `+0x22` and `+0x23`

Conceptually:

```c
format_two_hex_chars(&temp, value);
frame[+0x22] = temp[0];
frame[+0x23] = temp[1];
```

## Serial Sender

### Function

| Item | Value |
|---|---|
| Sender wrapper | `sub_418df0` |
| Address | `0x418df0` |
| Disassembly line | around `27905` |

### Behavior

The sender:

- Uses a serial handle/object context around `[ebp+0x180]`.
- Copies payload into an internal buffer around `[ebp+0x188]`.
- Calls `WriteFile` through `[ds:0x4551d4]`.
- Treats the outgoing frame as a C string.

Important consequence:

```text
Any embedded NUL byte truncates the transmitted payload.
```

This matters for frames that contain ETX followed by NUL, and especially for any command data containing zero bytes. The sender will stop at the first NUL.

### Builder/Sender Caller Pattern

Observed caller pattern:

1. Call `sub_42a430` to build a frame.
2. Copy returned builder output into a local stack buffer until NUL.
3. Call sender wrapper on object/global around `ds:0x46f528`.

Direct builder call sites observed around lines:

```text
31612, 31621, 32096, 32301, 32316, 32593, 36875
```

Direct sender wrapper call sites observed around lines:

```text
31630, 31634, 32331, 32335, 32601, 36879, 37016
```

## Receive / Report Handling

### `sub_41dd65` — Status Update Function

| Item | Value |
|---|---|
| Address | `0x41dd65` |
| Disassembly line | around `34355` |
| Associated strings | `fDataInquiryPause`, `intAsynchronousCommandWaiting`, `intExCmndDataInquiry` |

**Pseudocode summary:**

```c
void sub_41dd65(void* ecx) {
    sub_406d00();
    
    // Send 0x1f40 (8000) to UI element
    SendMessageA(ecx[0x52e], 0xb1, 0, 0x1f40);
    
    // Log "fDataInquiryPause"
    eax = sub_407170(&var_4, ecx[0x17]);
    SendMessageA(ecx[0x52e], 0xc2, 0, eax);
    sub_4471d7();
    
    // Log "intAsynchronousCommandWaiting"
    eax = sub_407170(&var_4, ecx[0x2a0]);
    SendMessageA(ecx[0x52e], 0xc2, 0, eax);
    sub_4471d7();
    
    // Log "intExCmndDataInquiry"
    eax = sub_407170(&var_4, ecx[0x570]);
    SendMessageA(ecx[0x52e], 0xc2, 0, eax);
    sub_4471d7();
    
    return sub_406d30();
}
```

**Interpretation:** This function updates the UI status bar with three status messages related to the data inquiry process. It reads string resources from the object and sends them to a UI element via `SendMessageA`.

### `sub_4208d5` — Main Receive Processor

| Item | Value |
|---|---|
| Address | `0x4208d5` |
| Disassembly line | around `38068` |
| Associated strings | `(RX-V)`, `Yamaha Receiver Editor Message`, `Sorry, this version doesn't support this model.` |

**Key behavior (from pseudocode):**

1. **Data availability check:**
   ```c
   if (SendMessageA(esi[0x53d], 0xf0, 0, 0) == 1) {
       // Data is available
       ebp = esi + 0x149c;  // receive buffer
       if (sub_446826() > 0x7530) {  // buffer > 30000 bytes
           // Progress update
           SendMessageA(arg_18, 0xb1, 0, 0x7530);
           SendMessageA(esi[0x52e], 0xc2, 0, 0x46df20);
       }
       eax = sub_446826();  // get data length
       SendMessageA(arg_18, 0xb1, eax, eax);
       SendMessageA(arg_18, 0xb7, 0, 0);
       // ... process data
   }
   ```

2. **State machine switch:**
   ```c
   switch (esi[esi[0x21a] * 4 + 0x68]) {
       case 255:  // 0xff
       case 8:    // 0x08
       case 28:   // 0x1c
           KillTimer(esi[0x7], 0x2);
           sub_418fb0(0x2, 0x0);
           esi[0x566] = 0x0;
           esi[0x2a1] = 0xffffffff;
           esi[0x21a] = esi[0x21a] + 1;
           break;
   }
   ```

3. **Command lookup:**
   ```c
   ebp = sub_42aac0(ebx);     // string → command ID lookup
   arg_4 = ebp;
   eax = sub_42aba0(ebp);      // command ID → model name lookup
   ```

4. **Model support check:**
   ```c
   if (sub_445648(var_1C, "Yamaha Receiver Editor Message", 1, ...) == 1) {
       if (arg_c != 0x7) {
           // "Sorry, this version doesn't support this model."
           sub_445648("Sorry, this version doesn't support this model.", ...);
       }
   }
   ```

**Interpretation:** This is the main receive processing function. It:
- Checks if serial data is available
- Manages a receive buffer (max 30000 bytes)
- Runs a state machine for command processing
- Looks up received command strings to IDs via `sub_42aac0`
- Maps command IDs to model names via `sub_42aba0`
- Shows error dialogs for unsupported models

### `sub_42aac0` — Command String to ID Lookup

| Item | Value |
|---|---|
| Address | `0x42aac0` |
| Table range | `0x4594c8` to `0x45951c` (stepping by 0xc = 12 bytes) |

**Pseudocode:**

```c
int lookup_command_id(char* command_string) {
    // Build CString from 5-char input
    CString input;
    input.GetBuffer(6);
    for (int i = 0; i < 5; i++) {
        input.SetAt(i, command_string[i]);
    }
    input.SetAt(5, 0);
    input.ReleaseBuffer(-1);
    
    // Search table
    int result = -1;
    for (int* entry = 0x4594c8; entry <= 0x45951c; entry += 0xc) {
        sub_447360(entry - 0x8);  // load string from table entry
        if (sub_434906(var_14, var_10) == 0) {  // compare strings
            result = *entry;  // store matched ID
        }
    }
    return result;
}
```

**Interpretation:** This is a reverse lookup that maps 5-character command strings (like "07A1B") to command IDs. The table at `0x4594c8..0x45951c` contains entries with:
- Offset -0x8: pointer to command string
- Offset 0x0: command ID (integer)

### `sub_42aba0` — Model ID to Name Lookup

| Item | Value |
|---|---|
| Address | `0x42aba0` |

**Pseudocode:**

```c* char* lookup_model_name(int model_id) {
    int index = model_id + 1;
    if (index <= 8) {
        switch (switch_table[index]) {
            case 0: return "UNKNOWN";
            case 1: return "RX-V1";
            case 2: return "RX-V3000";
            case 3: return "RX-V1000";
            case 4: return "RX-V3200";
            case 5: return "RX-Z1";
            case 6: return "RX-V3300";
            case 7: return "RX-V2300";
            default: return "RX-V2400";
        }
    }
    return "UNKNOWN";  // or ecx + 0x14
}
```

**Supported models:**

| Model ID | Model Name |
|---:|---|
| 0 | UNKNOWN |
| 1 | RX-V1 |
| 2 | RX-V3000 |
| 3 | RX-V1000 |
| 4 | RX-V3200 |
| 5 | RX-Z1 |
| 6 | RX-V3300 |
| 7 | RX-V2300 |
| 8+ | RX-V2400 |

## Relevant Strings / Debug Markers

| String | Address | Notes |
|---|---:|---|
| `(PC) Command` | `0x469354` | xrefs include `0x41bf02`, `0x41bf71`, `0x41c840`. |
| `intExCmndDataInquiry` | `0x469720` | xref `0x41de51` in `sub_41dd65`. |
| `(RX-V)` | `0x4699c4` | xref `0x420999` in `sub_4208d5`. |
| `fDataInquiryPause` | — | Status message in `sub_41dd65`. |
| `intAsynchronousCommandWaiting` | — | Status message in `sub_41dd65`. |
| `Yamaha Receiver Editor Message` | — | Dialog title in `sub_4208d5`. |
| `Sorry, this version doesn't support this model.` | — | Error message in `sub_4208d5`. |

## Helper Functions Identified

| Function | Address | Disassembly line | Role |
|---|---:|---:|---|
| `sub_436923` | `0x436923` | around `69135` | itoa wrapper (nibble to hex). |
| `sub_436950` | `0x436950` | around `69153` | core itoa-like conversion routine. |
| `sub_446f4c` | `0x446f4c` | around `93953` | likely CString assignment/copy helper. |
| `sub_4471d7` | `0x4471d7` | around `94172` | obtains char pointer from CString for copying formatted bytes into frame buffer. |
| `sub_447245` | `0x447245` | around `94219` | assigns static/literal string to CString. |
| `sub_447310` | `0x447310` | around `94306` | CString assignment/refcounting routine. |
| `sub_447360` | `0x447360` | — | loads string from table entry for comparison. |
| `sub_447641` | `0x447641` | around `94625` | ReleaseBuffer-like helper; `-1` triggers strlen behavior. |
| `sub_447669` | `0x447669` | around `94639` | GetBuffer-like helper; resizes and null-terminates. |
| `sub_4476ad` | `0x4476ad` | around `94669` | SetAt-like helper: writes one byte at index. |
| `sub_434906` | `0x434906` | — | string comparison function. |
| `sub_445648` | `0x445648` | — | MessageBox/dialog display function. |

## Confirmed Static String Region

Raw offset used for VMA `0x4681ac`:

```text
raw = vma - 0x400000
0x4681ac -> 0x681ac
```

Dump around that region:

```text
000681a0: 4400 0000 4300 0000 4200 0000 3030 0000  D...C...B...00..
000681b0: 3030 3030 0000 0000 2d00 0000 3900 0000  0000....-...9...
000681c0: 3800 0000 3700 0000 3600 0000 3500 0000  8...7...6...5...
000681d0: 3400 0000 3300 0000 3200 0000 3100 0000  4...3...2...1...
000681e0: 3000 0000 2e00 0000 302e 0000 494e 5641  0.......0...INVA
```

Relevant confirmed item:

```text
VMA 0x4681ac -> raw 0x681ac -> bytes 30 30 00 -> "00"
```

This is the fallback/invalid string used by `sub_407060` when `(value >> 4) >= 0x10`.

## Best Current Protocol Model

### Command Frame Construction

For ordinary commands:

```text
builder(this, id, value)
```

does roughly:

```c
if (id <= 0x6c) {
    handler = dispatch_table[id];
    frame[0] = STX;
    handler(frame + 1, id, value);
    frame[length - 1] = ETX;
} else if (id == 0xff) {
    write fixed special frame:
      0x11 '0' '0' '0' ETX NUL
} else {
    invalid path / CString cleanup / static pointer use
}
```

### Full-Record Commands

For handlers using full record style (`0x42a5e5`):

```text
STX + record[id][value] + ETX
```

Where each record is 5 ASCII bytes, and `value` selects which record to use.

### Prefix + Value Commands

For handlers using prefix/value style:

**Handler A (`0x42a4fd`):**
```text
STX + first_3_record_chars + two_formatted_hex(value + 0x26 if nonzero) + ETX
```

**Handler B (`0x42a589`):**
```text
STX + first_3_record_chars + two_formatted_hex(value) + ETX
```

The two formatted characters are uppercase hexadecimal digits representing a byte-sized value, possibly adjusted by `+0x26` for handler `0x42a4fd`.

### Transmission

```c
WriteFile(serial_handle, frame_as_c_string, length_up_to_NUL);
```

Embedded NUL truncation is important.

## Confidence Levels

### High Confidence

- The executable contains a central command builder and serial sender wrapper.
- Command records are stored in a table accessed through `sub_42aaa0`.
- Record stride is 5 bytes.
- There are two major ordinary frame shapes:
  - `STX + 5 ASCII + ETX`
  - `STX + 3 ASCII + 2 formatted ASCII + ETX`
- Handler dispatch table and ID ranges were extracted into CSV.
- Sender uses `WriteFile` and treats payload as a C string.
- Special builder path for `id == 0xff` writes `11 30 30 30 03`.
- Static fallback string at `0x4681ac` is `"00"`.
- Handler `0x42a589` formats value directly (no `+0x26` adjustment).
- Handler `0x42a5e5` copies all 5 record bytes with value-based selection.
- The dispatch mechanism uses a two-level table (byte table + pointer table).
- All three handlers use the common epilogue at `0x42a603` to write ETX + NUL.

### Medium Confidence / Strongly Supported

- `sub_407075` formats two uppercase hex nibbles for a byte-sized value.
- The final CString constructed by `sub_407075` is:
  ```text
  high_hex_digit low_hex_digit NUL
  ```
- Handler `0x42a4fd` applies `+0x26` to nonzero values before formatting.
- Helper functions near `0x4476xx` are MFC/CString-like `GetBuffer`, `ReleaseBuffer`, and `SetAt`.
- `sub_42aac0` performs reverse command string → ID lookup.
- `sub_42aba0` maps model IDs to Yamaha receiver model names.
- `sub_4208d5` is the main receive processing function with a state machine.

### Not Fully Resolved

- Exact protocol meaning of the `+0x26` adjustment.
- Whether there is an actual checksum calculation or just a formatted data byte in some commands.
- Complete RX-V reply parsing format.
- Complete UI action to command ID mapping.
- Negative integer edge cases in the formatter, although normal protocol values likely fit into byte-sized unsigned ranges.
- Exact contents of the command string lookup table at `0x4594c8..0x45951c`.

## Recommended Next Steps If Analysis Is Resumed Later

1. Compare generated frames against known Yamaha RX-V RS-232C protocol documentation.

2. Trace UI handlers to builder calls and map specific controls to command IDs.

3. Determine whether the two formatted characters are:
   - pure hex-encoded value,
   - checksum,
   - or family-specific encoded data.

4. Decode the command string lookup table at `0x4594c8..0x45951c` to map command strings to IDs.

5. If safe instrumentation is available, log frames before `WriteFile` and compare against protocol captures.

6. Analyze `sub_446826` (buffer length function) and `sub_434906` (string comparison) for complete receive processing understanding.

7. Investigate the relationship between the `+0x26` adjustment and Yamaha's RS-232C protocol specification.

## Final Short Takeaway

The binary's command generation is largely dictionary-driven:

```text
ID selects a command record pool.
Value either selects one of several 5-byte records or is formatted into two ASCII characters appended after a 3-byte command prefix.
Frames are sent as C strings over serial, so embedded NUL bytes truncate transmission.
The special ID 0xff path emits a fixed short frame: 11 30 30 30 03.
```

### ID-to-Handler Mapping Summary

| ID Range | Handler | Frame Type | Value Usage |
|---|---|---|---|
| `0x00..0x2f` | `0x42a5e5` | Full record (5 ASCII) | Selects record from table |
| `0x30, 0x31, 0x34` | `0x42a4fd` | Prefix + 2 hex (with `+0x26`) | Formatted as hex (adjusted) |
| `0x32, 0x36..0x45, 0x48, 0x49` | `0x42a589` | Prefix + 2 hex (direct) | Formatted as hex (direct) |
| `0x33, 0x35, 0x46, 0x47, 0x4a..0x6c` | `0x42a5e5` | Full record (5 ASCII) | Selects record from table |
| `0xff` | (special) | Fixed frame `11 30 30 30 03` | None |

---

## Update: Reply Path and Inquiry Frames (2026-10-11)

### Decoded Reply Lookup Table

The table at VMA `0x4594c8` (stride 12 bytes: 8-byte inline string + 4-byte int ID)
contains receiver-to-PC reply strings used by `sub_42aac0` (reverse string→ID lookup):

| Reply String | ID | | Reply String | ID |
|---|---|---|---|---|
| `R0073` | 0 | | `R0114` | 4 |
| `R0090` | 1 | | `R0133` | 5 |
| `R0088` | 2 | | `R0132` | 6 |
| `R0112` | 3 | | `R0161` | 7 |

`sub_42aba0` maps those IDs to model names via `switch_table[model_id + 1]`:

| ID | Model |
|---:|---|
| -1 | UNKNOWN |
| 0 | RX-V1 |
| 1 | RX-V3000 |
| 2 | RX-V1000 |
| 3 | RX-V3200 |
| 4 | RX-Z1 |
| 5 | RX-V3300 |
| 6 | RX-V2300 |
| 7+ | RX-V2400 |

These `R0xxx` strings are the receiver's identity replies — the PC sends an inquiry
frame and the receiver responds with a 5-character ASCII model-ID string. This is
the mechanism behind "Auto Device Finder found" / "Model mismatched" in the UI.

### Inquiry Frames (Data Request)

The only literal builder call sites in the binary are inquiry pairs, each followed
by a receive-buffer check (`sub_446826` vs. the 30 KB buffer at `esi+0x149c`):

| Address | Call | ID | Value | Frame |
|---|---|---|---|---|
| `0x41be45` | `builder(0x2e, 1)` | `0x2e` | 1 | `STX "00000" ETX` |
| `0x41be68` | `builder(0x2f, N)` | `0x2f` | 0–8 | `STX "2010N" ETX` |
| `0x41c702` | `builder(0x2e, 1)` | `0x2e` | 1 | `STX "00000" ETX` |
| `0x41c732` | `builder(0x2f, 0)` | `0x2f` | 0 | `STX "20100" ETX` |

These are the **query frames** that trigger a reply from the receiver.

### Numeric Command Family (IDs 0x2e–0x6b)

The full command table contains a numeric family of 5-digit-record commands:

| ID | Records | Purpose |
|---|---|---|
| `0x2e` | `00001`, `00000` | Inquiry mode on/off |
| `0x2f` | `20100`–`20108` | Data page request |
| `0x30`–`0x32` | `23000`, `23100`, `23200` | Volume (prefix+value) |
| `0x33` | `23300`, `23301` | |
| `0x34` | `23400` | |
| `0x35` | `23800` | |
| `0x36`–`0x3f` | `24000`–`24900` | Tone/balance/etc (prefix+value) |
| `0x41`–`0x45` | `25100`–`25400` | |
| `0x46`–`0x50` | `25700`–`26900` | |
| `0x53`–`0x5c` | `27000`–`27900` | |
| `0x61` | `28000`–`28002` | |
| `0x62`–`0x6b` | `29000`–`29900` | |

### Report/Configuration Download

Strings in the binary confirm a full configuration download/report subsystem:

- `Downloading Configuration. Please Wait`
- `(RX-V) Report`
- `Receiver Editor Configuration Report`
- `intExCmndDataInquiry`
- `fDataInquiryPause`
- `intAsynchronousCommandWaiting`
- `Command Waiting Counter Cleared`

Report content fields: `    Input Information`, `1. Current Setting`,
`Straight ( DSP Program`, `Assigned I/O`, `Optical IN`, `Optical OUT`,
`Component Video`, `FM :`, `AM :`, `107.9 MHz`, `1710 kHz`.

### Supported Models (from `sub_42aba0`)

RX-V1, RX-V3000, RX-V1000, RX-V3200, RX-Z1, RX-V3300, RX-V2300, RX-V2400.
**Note: RX-V2500 is NOT in this list** — it may not respond to inquiry frames
or may use different page codes. Empirical testing is required.

### Confidence

- **High confidence**: Reply strings, inquiry frames, model-name mapping, and
  numeric command family are directly decoded from binary data.
- **Medium confidence**: The `R0xxx` reply format and `2010N` page semantics are
  inferred from code flow (send inquiry → wait → read buffer) and string context.
- **Unresolved**: Full reply framing (STX/ETX delimiters, digit field layout),
  page-to-field mapping, and whether RX-V2500 actually responds.

---

## Update: Live Report Capture and Decoding (2026-10-11)

### Empirical Confirmation

Live capture on RX-V2500 confirms the receiver sends **unsolicited status
reports** over RS-232. Reports are event-driven (one per change) and use a
different frame format from commands.

### Report Frame Format

```
STX + type(1 byte) + id(1 byte) + value(1 byte) + ETX
```

Encoded as 6 ASCII hex chars (3 bytes) between STX and ETX — 8 bytes total,
vs. 7 bytes for commands.

### Report Types

| Type | Meaning |
|---|---|
| `0x00` | Setting change (single field) |
| `0x01` | ? (observed once with speaker_a_off) |
| `0x10` | Volume change |
| `0x30` | Group status (multiple fields reported together) |

### Decoded Field IDs

| ID | Field | Values |
|---|---|---|
| `0x21` | Input selection | 0=phono, 1=CD, 2=tuner, ... |
| `0x22` | ? (changes with input/sound mode) | 0x00 with CD, 0x05 with straight |
| `0x23` | Mute | 0=off, 1=on |
| `0x26` | Volume | 0x97–0x9F observed (151–159), 0.5 dB/step |
| `0x28` | Sound mode | 0x8E=straight, 0x34=2ch stereo |
| `0x2C` | Sleep timer | 0x04=off |
| `0x82` | Night mode | 0x00=off |
| `0x8C` | Pure direct | 0x01=on |

### Group Status Reports (type=0x30)

IDs 0x10–0x14 always appear together when certain settings change. Likely a
"main zone status" summary:

| ID | Meaning (tentative) |
|---|---|
| `0x10` | Power (0x01 = on) |
| `0x11` | ? |
| `0x12` | ? |
| `0x13` | ? |
| `0x14` | ? |

### Volume Encoding

Volume reports use ID `0x26` with values in range 0x97–0x9F (151–159). Each
step = 0.5 dB. The exact dB mapping requires calibration against the front
panel display.

### Heartbeat — NOT present

The `30 00 00` frame seen in the first capture was **not** a periodic heartbeat.
A 5-second idle listen produced **zero bytes**. Reports are purely event-driven:
the receiver sends a frame only when a state change occurs (keypress, command,
or input signal change). This means status must be tracked by maintaining state
from reports — there is no polling mechanism.

### Query Responses

The `0x2e`/`0x2f` inquiry frames produce responses:
- `QUERY_INIT` ("00000") → `102300` + `300000`
- Page queries ("20100"–"20108") → `300000` each

The `300000` response appears to be an acknowledgment or "no data" indicator.
The `102300` response is a single status report.

---

## Update: Systematic Report Mapping (2026-10-11)

### Method

Sent safe commands (no volume changes) via RS-232 and captured unsolicited
reports. All commands were non-destructive (mute, input select, sound mode,
tone controls, sleep timer, night mode, speaker toggles).

### Confirmed Report Types

| Type | Meaning | Example |
|---|---|---|
| `0x00` | General setting change | mute, input, sleep |
| `0x01` | Sound mode change | straight → `01 28 8E` |
| `0x02` | Night mode change | night_off → `02 82 00` |
| `0x10` | Volume change | vol_up → `10 26 9D` |
| `0x30` | Group status (IDs 0x10–0x14) | main zone summary |

### Confirmed Field IDs

| ID | Field | Values | Evidence |
|---|---|---|---|
| `0x21` | Input selection | 0=phono, 1=CD, 2=tuner | input_phono/cd/tuner |
| `0x22` | ? (correlates with input/mode) | 0x00, 0x05 | input_cd, straight |
| `0x23` | Mute | 0=off, 1=on | mute_on/off |
| `0x26` | Volume | 0x97–0x9F | volume keypresses |
| `0x28` | Sound mode | 0x8E=straight, 0x34=2ch stereo | straight, stereo_2ch |
| `0x2C` | Sleep timer | 0x04=off | sleep_off |
| `0x82` | Night mode | 0x00=off | night_off |

### Group Status Reports (type=0x30)

IDs 0x10–0x14 always appear together when input, sound mode, or speakers
change. Likely a main-zone status summary:

| ID | Tentative Meaning |
|---|---|
| `0x10` | Power (0x01 = on) |
| `0x11` | ? |
| `0x12` | ? |
| `0x13` | ? |
| `0x14` | ? |

### Commands That Do NOT Generate Reports

- `bass_0`, `treble_0`, `balance_0` — no response (may not be supported or
  may require specific conditions)

### Key Architectural Finding

Reports are **purely event-driven**. The receiver sends nothing when idle
(verified with 5-second passive listen = 0 bytes). There is no polling
mechanism. Status must be tracked by maintaining state from reports over a
persistent connection.

---

## Complete Report Format (2026-10-11)

### Frame Structure

All reports use the same 8-byte frame:

```
STX (0x02) + type (2 hex chars) + id (2 hex chars) + value (2 hex chars) + ETX (0x03)
```

Encoded as 6 ASCII hex characters between STX and ETX.

### Report Types

| Type | Constant | Meaning |
|---|---|---|
| `0x00` | `REPORT_SETTING` | General setting change |
| `0x01` | `REPORT_SOUND_MODE` | Sound mode change |
| `0x02` | `REPORT_NIGHT_MODE` | Night mode change |
| `0x10` | `REPORT_VOLUME` | Volume change |
| `0x30` | `REPORT_GROUP` | Group status (IDs 0x10–0x14) |

### Field ID Map

| ID | Field | Values | Source |
|---|---|---|---|
| `0x21` | Input selection | 0x00–0x0C, gaps at 0x08/0x0B | Empirical + exe name table |
| `0x22` | Per-input attribute (meaning TBD) | `0x00` (CD/DVD/DTV/CBL/SAT/V-AUX), `0x02` (DVR/VCR2), `0x05` (PHONO/TUNER/CD-R/MD/TAPE/VCR1) | Empirical |
| `0x23` | Mute | 0=off, 1=on | Empirical |
| `0x26` | Volume | dB = value/2 − 80 | Empirical |
| `0x28` | Sound program + STRAIGHT flag | program value, `0x80` = STRAIGHT | Empirical |
| `0x2C` | Sleep timer | 0=120min, 1=90min, 2=60min, 3=30min, 4=off | Empirical |
| `0x2D` | Extended surround | 0=off, 1=ES/EX, 3=auto, 5=PLIIx movie, 6=PLIIx music | Empirical |
| `0x2F` | Speaker B | 0=off, 1=on | Empirical |
| `0x82` | Night mode | 0=off, 2=cinema, 5=music | Empirical |
| `0x8C` | Pure Direct | 0=off, 1=on (usually type `0x20`) | Empirical |

### Input Name Table (Pure Direct OFF)

The input value is a **bitfield** — bit 4 (`0x10`) indicates Pure Direct is on.
With Pure Direct on, all input values were offset by `+0x10`.

The receiver uses values `0x00`–`0x0C` but **skips `0x08` and `0x0B`**, giving
11 distinct values. That matches exactly the 11-entry name table in
`YamahaReceiverEditor3.exe` at VMA `0x459524` (15-byte records, accessor at
`0x42ac50`: `eax = index*15 + 0x459524`):

| Value | Name | Select record |
|---:|---|---|
| 0x00 | PHONO | `07A14` |
| 0x01 | CD | `07A15` |
| 0x02 | TUNER | `07A16` |
| 0x03 | CD-R | `07A19` |
| 0x04 | MD/TAPE | `07AC9` |
| 0x05 | DVD | `07AC1` |
| 0x06 | DTV | `07A54` |
| 0x07 | CBL/SAT | `07AC0` (alias `07ACA`) |
| ~~0x08~~ | *(unused — gap)* | — |
| 0x09 | VCR1 | `07A0F` |
| 0x0A | DVR/VCR2 | `07A13` (alias `07AC8`, also `07EA0`) |
| ~~0x0B~~ | *(unused — gap)* | — |
| 0x0C | V-AUX | `07A55` |

Command-table ID `0x02` holds **13 records** for **11 inputs** — two pairs are
aliases. Values `0x08` and `0x0B` were never produced by any record.

**Not yet verified:** the middle names depend on the gap-removal mapping
(endpoints 0x00=PHONO and 0x0C=V-AUX are confirmed). A front-panel eyeball
check would settle it definitively.

### Connection-Open Status Dump — this is the "full status dump"

**The receiver emits a status dump when the RS-232 port is (re)opened.** This
explains the burst previously (mis)attributed to toggling Pure Direct: it was
the dump from ser2net reopening the serial port for a new TCP client.

Observed dump (connection 1, 9 frames):

```
30 14 00      group status
10 21 06      input = 0x06 (DTV)
30 10 02      speakers[0x10]
30 11 03      speakers[0x11]
30 12 00      group status
30 13 00      group status
10 22 00      per-input attribute
10 28 17      sound program = 0x17 (7ch Stereo)
20 8C 00      Pure Direct = off
```

A variant seen earlier also carried `10 B0 00`, `10 20 00`, `10 20 02`,
`30 00 01`, `30 36 01`, `30 3C 01` — the content is not perfectly stable.

**There is no polling command.** Inquiry frames `02 30 30 30 30 30 03`
(`00000`) and `02 32 30 31 30 4E 03` (`2010N`, N=0..8) all answer with the
same bare ACK `30 00 00` and no data. State must be tracked from the
connection dump plus subsequent event reports.

### Pure Direct Blocks Reports

**Critical finding:** When Pure Direct is ON, the receiver suppresses most
RS-232 reports. Remote input changes produced **zero** reports with Pure Direct
on. With Pure Direct off, all reports flow normally.

Additionally, Pure Direct being on adds `0x10` to the input value bitfield,
which initially made the input mapping appear non-sequential.

### Report "type" is a category, not a discriminator

The same field ID appears under several type bytes — e.g. `0x28` shows up as
`0x00`, `0x01` and `0x10`; `0x22` as `0x00` and `0x01`. **Decoding must be
keyed on the field ID**, with the type retained only for diagnostics:

| Type | Constant | Observed use |
|---|---|---|
| `0x00` | `REPORT_SETTING` | most setting changes |
| `0x01` | `REPORT_SOUND_MODE` | same fields as `0x00`, different category |
| `0x02` | `REPORT_NIGHT_MODE` | night mode |
| `0x10` | `REPORT_MAIN_ZONE` | connection dump: input/attr/sound mode |
| `0x20` | `REPORT_PURE_DIRECT` | id `0x8C` only |
| `0x30` | `REPORT_GROUP` | group status + ACK (`30 00 00`) |

Type `0x10` carries the connection-dump snapshot (input, per-input attribute,
sound program). Types `0x20` and `0x30` with ids `0x20`, `0xB0`, `0x36`,
`0x3C` appear only in the less common dump variant and remain unidentified.

### Delta-Reporting Pattern (verified across all inputs)

Sending the same input command twice produces **different report sets**:

**Command #1 (input change):** 4–5 reports
```
30 14 00          — group status (always first)
00 21 XX          — input change (the actual new input)
30 10 01          — speakers[0x10]
30 11 00          — speakers[0x11]
30 12 00          — group status
```

**Command #2 (same input, no change):** 5–6 reports
```
00 22 XX          — per-input attribute (re-broadcast, not an input change)
30 10 01          — speakers[0x10]
30 11 00          — speakers[0x11]
30 12 00          — group status
30 13 00          — group status
```

Redundant commands produce a different report set (no input change report, but
a `00 22` attribute report instead). A third identical command often produces
no notable field reports at all.

### Group `0x10` / `0x11` = active speaker / channel bitmap

`0x10` and `0x11` always travel together and track both the speaker setup and
the input's channel layout:

| Situation | `0x10` | `0x11` |
|---|---|---|
| Speaker A on, analog 2ch input | `0x01` | `0x00` |
| DTV (digital input) | `0x02` | `0x03` |
| Speaker A off (B on) / MULTI-CH-like input | `0x09` | `0x07` |

Group `0x00` doubles as the inquiry ACK (`30 00 00`); `30 00 01` was seen in
the connection dump. `0x36` and `0x3C` only appear in the dump variant.

### Implications for State Tracking

1. **Open the connection and read the dump first** — that is the only way to
   learn the initial state (input, sound program, Pure Direct).
2. Then accumulate event reports over time; there is no polling mechanism.
3. Redundant commands produce different reports than actual changes.
4. Decode by field ID, not by type byte.

### Volume Encoding — CONFIRMED

Volume reports use ID `0x26`. The formula is: **dB = value/2 - 80**

- Volume 0 = -80.0 dB (minimum/muted)
- Volume 151 = -4.5 dB (typical listening level)
- Volume 188 = +14.0 dB (maximum for RX-V2500)

Range: 0–188 (0–255 possible, but 188 is the RX-V2500 max).

### Implementation Status

- `ReportParser` class implemented in `yamaha_rs232_controller.py`
- `monitor` mode listens for reports and maintains state
- `status` command prints current state (from parser or state file)
- State can be persisted to JSON file for external consumption

### Sound Program Values (field ID `0x28`) — ENCODING SOLVED

Swept all 26 sound-mode commands with Pure Direct off. Each returned a
`type=0x00, id=0x28` report with the following **program** value:

| Value | Program | | Value | Program |
|---:|---|---|---:|---|
| `0x00` | Hall Munich | | `0x24` | Spectacle |
| `0x05` | Hall Vienna | | `0x25` | Sci-Fi |
| `0x09` | Hall Freiburg | | `0x28` | Adventure |
| `0x0E` | Hall Bottom Line | | `0x29` | General |
| `0x10` | Hall Roxy | | `0x2C` | Pro Logic |
| `0x14` | Disco | | `0x2D` | Pro Logic Enhanced |
| `0x16` | Game | | `0x34` | 2ch Stereo |
| `0x17` | 7ch Stereo | | `0x36` | THX Cinema |
| `0x18` | Pop/Rock | | | |
| `0x1C` | Classical | | | |
| `0x20` | Mono Movie | | | |
| `0x21` | TV Sports | | | |

**`0x28` value = program value, plus bit 7 (`0x80`) = STRAIGHT flag.**

STRAIGHT does not have its own program value — it overlays the *last selected
program*. Verified end-to-end:

| Program set first | then STRAIGHT → | decode |
|---|---|---|
| Hall Munich (`0x00`) | `0x80` | `0x80 \| 0x00` |
| Hall Vienna (`0x05`) | `0x85` | `0x80 \| 0x05` |
| Hall Bottom Line (`0x0E`) | `0x8E` | `0x80 \| 0x0E` |
| Hall Roxy (`0x10`) | `0x90` | `0x80 \| 0x10` |
| 7ch Stereo (`0x17`) | `0x97` | `0x80 \| 0x17` |
| Spectacle (`0x24`) | `0xA4` | `0x80 \| 0x24` |
| TV Sports (`0x21`) | `0xA1` | `0x80 \| 0x21` |
| Sci-Fi (`0x25`) | `0xA5` | `0x80 \| 0x25` |
| 2ch Stereo (`0x34`) | `0xB4` | `0x80 \| 0x34` |
| THX Cinema (`0x36`) | `0xB6` | `0x80 \| 0x36` |

This retroactively explains every previously "mysterious" value: `0xA5`, `0x8E`,
`0x90`, `0x97`, `0xA1`, `0x85`, `0xA4`, `0xB4`, `0xB6` were all *STRAIGHT +
the previously active program*, never distinct modes. Decode with
`program = value & 0x7F`, `straight = bool(value & 0x80)`.

The `0x80` bit also appears in the exe at `0x46f308+` as a per-program flag
byte (`or al,0x80` before storing), corroborating the interpretation.

**Note:** the five *extended surround* commands produce **no `0x28` report at
all** — they report on field `0x2D` instead (see field ID map).

### Extended Surround — field `0x2D` (resolved)

| Report | Command | Meaning |
|---|---|---|
| `00 2D 00` | `ext_surround_off` (`07EB9`) | off |
| `00 2D 01` | `07EB8` / `ext_surround_es_ex` (state-dependent) | ES/EX |
| `00 2D 03` | `ext_surround_auto` (`07E7C`) | auto |
| `00 2D 05` | `ext_pliix_movie` (`07EDD`) | PLIIx movie |
| `00 2D 06` | `ext_pliix_music` (`07EDE`) / `ext_surround_es_ex` | PLIIx music |

The observed value for the *same* command differed between sessions (`07E7D`
→ `0x06` while in 7ch Stereo, → `0x01` while in Straight), so the reported
value depends on the active program's capabilities. Values `0x02` and `0x04`
have not been observed.

### Sleep Timer — field `0x2C` (fully mapped)

Command-table ID `0x10` records map in reverse order:

| Value | Meaning | Record |
|---:|---|---|
| `0x00` | 120 min | `07EB4` |
| `0x01` | 90 min | `07EB5` |
| `0x02` | 60 min | `07EB6` |
| `0x03` | 30 min | `07EB7` |
| `0x04` | OFF | `07EB3` |

### Speaker B — field `0x2F` (resolved)

`speaker_B_on` (`07EAD`) → `00 2F 01`; `speaker_B_off` (`07EAE`) → `00 2F 00`.
`speaker_A_on/off` produce no `0x2F` report but change group `0x10`/`0x11`.

### Phase A (live probing for the Home Assistant integration)

#### Power state — fields `0x20` / `0xB0` (resolved)

Power cycling over RS-232 works and reports its own state:

| Action | Reports |
|---|---|
| `power_off` (`07A1E`) | `00 B0 00` then `00 20 00` |
| `power_on` (`07A1D`) | `00 20 02` then group frames (`30 00 01`, `30 15 00`, `30 36 01`, `30 3C 01`) |

- Field `0x20`: `0x02` = ON, `0x00` = standby. This settles the old mystery
  IDs `0x20`/`0xB0` from the "rarer dump variant" — they were **power
  reports**, not dump noise.
- **In standby the receiver goes silent**: no reports, no ACKs, no dump on
  serial reopen. Commands (including `power_on`) may be swallowed for a
  while; after a ser2net restart the link recovered and `07A1D` worked.
  Implication for the daemon: on reconnect, if nothing is heard, retry
  power_on; state = unknown until any report arrives.
- Command ACKs (`30 00 00`) and echo (`30 00 01`) still flow when powered.

#### Absolute volume set — prefix `230` (resolved)

Format: `STX + "230" + hex(wire) + ETX` where **`wire = raw + 0x26`**
(handler `0x42a4fd`'s +0x26 adjustment, now verified live):

- Set raw 169 → wire `0xCF` (`230 CF`); receiver echoes `30 26 CF`
  (**type `0x30` = command echo of the WIRE byte**, not state), then
  reports the real state as `00 26 A9` / `10 26 A9`.
- Probe `230 4E` (wire 78) landed volume at raw 40 = 78 − 38. Confirms
  the receiver subtracts 0x26. Range 0..188 (0x00, then 0x27..0xE2).
- **Parser rule**: never treat type `0x30` frames as state — they are
  echoes. State comes only from types `0x00`/`0x01`/`0x02`/`0x10`.
- Edge case: one relative step after power-on was swallowed (echo but no
  state change) — commands right after wake-up may need a retry/confirm
  loop in the daemon.

> **Correction (2026-10-12, Phase B panel ground-truth):** everything
> above about volume *units* is wrong by one — the offset recovered from
> the exe (`0x26`) is off by one; the receiver uses **`0x27`**:
>
> - **`wire = raw + 0x27`** for both `230` sets and volume *reports*
>   (`00 26 xx` events and `10 26 xx` dumps). Calibration: set byte 128
>   → panel **−35.5 dB** (raw 89 = 128−39); set byte 168 → panel
>   **−15.5 dB** (raw 129); report byte 169 ↔ panel **−15.0 dB** (raw
>   130) — observed three separate times. So `00 26 A9` meant raw 130 =
>   −15.0 dB, not +4.5 dB. (The Phase A "probe `230 4E` landed raw 40"
>   line was a self-consistent artifact: set byte == subsequent report
>   byte under *any* symmetric offset, so it could never distinguish
>   0x26 from 0x27.)
> - **`230` sets are applied silently**: the receiver echoes the wire
>   byte and sends *no* state report — the echo **is** the ack and the
>   value **did** change. (Phase A's "then reports `00 26 A9`" was a
>   report from something else.)
> - **Volume keys are display-wake gated**: the first vol up/down click
>   only reveals the current level on the panel (no step, and — unlike
>   adjusting steps — **no serial report**); only follow-up clicks while
>   the level is displayed actually step ±0.5 dB. That made the old
>   vol_down+vol_up "net-zero probe" a *wake + real up-step* = +0.5 dB
>   leak per daemon restart.
>
> See "Volume units, resolved" in Phase B for the full story.

#### STRAIGHT — on/off pair (resolved)

Table ID `0x13` = `07EE0|07E27` is an **on/off pair**, verified live:
`07E27` → `00 28 36` (straight off, THX preserved), `07EE0` → `00 28 B6`
(straight back on). No toggle-state logic needed — two explicit commands.

#### Connection-open dump contents (updated)

A fresh serial open reliably yields (sampled with input DTV, STRAIGHT+THX,
volume 169): `30 14 00`, `01 22 00`, `10 21 06`, `30 10 02`, `30 11 03`,
`30 12 00`, `30 13 00`, `10 22 00`, `10 28 B6`, **`10 26 A9` (volume —
confirmed present)**, `10 2E 01`, `30 10 09`, `30 11 00`, `30 10 01`.
So the dump alone seeds: input, volume, sound mode/straight, speaker
bitmap, `0x22` attr, and `0x2E=1`. Fields NOT in the dump: mute, sleep,
night mode, ext surround, speaker B, pure direct flag (`0x8C`).

**Caveat**: the dump only appears when ser2net actually reopens
`/dev/ttyUSB0`. ser2net (`kickolduser: true`) keeps the serial port open
between TCP clients, so a new TCP client often gets *no* dump. The daemon
should hold its connection permanently and treat reseeding (restart
ser2net or use a reconnect hook) as an explicit operation.

### Phase B (resident daemon: `rxv2500d`)

A persistent daemon now owns the ser2net link and publishes receiver
state to MQTT with Home Assistant discovery (`rxv2500d.py`, systemd
service `rxv2500d` on the Pi, config `/etc/rxv2500d.conf`, persisted
state `~/yamaha/rxv2500d_state.json`). Design and measured behavior:

- **Link ownership**: one persistent TCP connection to `localhost:2500`
  with exponential-backoff reconnect; a serialized command queue so
  probes/commands never interleave; frame extraction tolerant of junk
  and split frames.
- **State model**: event-driven only — no polling. State = rare dump +
  accumulated event reports + persisted JSON (restored on every
  restart; flush throttled to ~1 s). Retained per-field MQTT topics
  plus a retained JSON blob; availability via LWT.
- **HA discovery**: 13 entities (power/mute/straight/speaker B switches,
  input/sound program/ext surround/sleep/night selects, volume-dB
  number, pure-direct + link binary sensors, reseed button).
- **Seeding after (re)connect**: wait up to 8 s for a dump; if none,
  send a bare-ACK liveness inquiry (`20100`) — ACK ⇒ powered, silence
  ⇒ standby. No volume probing (see below).

#### ser2net lifecycle & dump scarcity (measured)

- ser2net opens `/dev/ttyUSB0` when the first TCP client connects and
  **closes it when the last client leaves** (correcting the earlier
  `kickolduser` assumption).
- **Dumps almost never come back**: after connection gaps of 0, 45,
  120 and 300 s, and even after a full ser2net restart, a reconnect
  produced **zero** dump frames. Only a spontaneous reopen (observed
  after hours) yields one. ⇒ The daemon must treat dumps as a bonus
  and seed from the liveness inquiry + persisted state instead.

#### Command acknowledgement semantics (measured)

| Command type | Receiver response when value changes | When value unchanged |
|---|---|---|
| Most fields (mute, straight, sleep, night, speaker B, input…) | echo (`30 xx vv`) **+** state report `00 xx vv` | echo + redundant state report of same value |
| Volume set (`230`) | **echo only — value changes silently, no report ever** | echo only |
| Relative volume keys (vol up/down) | state report of new value — but only for *adjusting* steps | display-wake click (first press after ~seconds idle): **no step, no report** |

- Power-on can swallow the first command after wake-up (retry + bare-ACK
  inquiry fallback in the daemon's power job).
- `cmd/reseed` (reconnect) verified: 0.3 s, state preserved, availability
  never flips to offline.

#### Volume units, resolved (2026-10-12, panel ground truth)

The whole volume decode was wrong; settled by having the user read the
front panel while controlled frames were sent (DEBUG logging every raw
frame). Three separate discoveries, all now fixed in daemon + parser:

1. **The wire offset is `0x27`, not `0x26`.** Both `230` sets and volume
   reports use `byte = raw + 0x27` (raw = half-dB above −80.0). The
   `0x26` constant inherited from the exe RE was off by one, and it
   caused every "wire vs raw" confusion in this phase. Calibration
   points (all exact, read off the panel): set byte 128 → **−35.5 dB**
   (raw 89); set byte 168 → **−15.5 dB** (raw 129); report byte 169 ↔
   **−15.0 dB** (raw 130, observed three times); report byte 121 ↔
   **−39.0 dB** (raw 82, after one vol-up step from raw 81). The old
   decode (`value/2 − 80`) read ~**+19.5 dB too high**. The Phase A
   "probe `230 4E` landed raw 40" could never have distinguished the
   offsets — set byte equals the subsequent report byte under any
   symmetric offset.
2. **`230` sets are silent**: the receiver applies them immediately but
   **never sends a state report** — the echo *is* the ack. The daemon
   used to log "acked by echo (value unchanged)" and leave state stale;
   it now records the intended raw optimistically (verified: set to
   −15.0 updated the HA topic instantly with zero receiver reports).
3. **Volume keys are display-wake gated** (user-observed mechanism):
   the first vol up/down press after a few idle seconds only *reveals*
   the current level on the panel — no step, and **no serial report**;
   only follow-up presses while the level is displayed actually step
   ±0.5 dB. This made `vol_down` *look* like a no-op and turned the old
   "net-zero" seed probe (vol_down + vol_up) into a **wake + real
   up-step = +0.5 dB leak per daemon restart** — the cause of the
   volume creep seen earlier in Phase B. The probe is deleted
   (tombstoned in code with the reasoning).

End state: daemon state in raw units; volume −15.0 dB restored per user
preference with panel/HA agreement exact; input seeded to DTV via a
redundant `set/input` (reports its own field, zero change). Residual
low-priority check: the *dump* volume frame (`10 26 …`) is decoded with
the same `−0x27` — consistent with the long-standing −15.0 dB reading,
but confirm against the panel the next time a spontaneous dump arrives.

#### Daemon bugs found & fixed during Phase B

- Command table comment-layout bug (two-column comments had commented
  out `PROGRAM_TO_RECORD` entries).
- **Missing `subscribe()`** on `set/#` and `cmd/#` — all MQTT commands
  were silently ignored at first deploy.
- Volume decode/ack/probe bugs (see above).
- Echo-weak-ack logged at INFO after downgrading from WARNING.

### Phase C (Home Assistant validation, 2026-10-12)

User-tested live from the HA UI against the running daemon + broker:

- **Power**: standby and wake from HA both work (the power job's
  retry + bare-ACK inquiry fallback carries the wake-up reliably).
- **Volume, both directions**: HA slider → receiver (panel confirms the
  silent `230` apply); remote steps → HA state within ~1 s. Note the
  receiver's display-wake presses (first click, no step) emit no serial
  report, so HA only follows *adjusting* steps — by design, not lag.
- **Entity inventory**: 13 discovery configs retained
  (4 switches, 5 selects, 1 number, 2 binary sensors, 1 button) with all
  state topics retained and exact. Select paths proven end-to-end with
  redundant sets (option string exactly as HA sends it):
  `set/input DTV` → report `00 21 06`; `set/sound_program STEREO_7CH`
  → report `00 28 17`. Zero change, real acks.
- **Sound-mode byte semantics observed**: the straight on/off toggle
  flips bit `0x80` of the sound-mode byte while preserving the program —
  `0x97` ↔ `0x17` (STRAIGHT+STEREO_7CH / STEREO_7CH), earlier
  `0xB6` ↔ `0x36` (STRAIGHT+THX_CINEMA / THX_CINEMA).
- **Orphan entities diagnosed and purged**: two doubled-prefix ghosts
  (`select.yamaha_rx_v2500_yamaha_rx_v2500_input`,
  `..._sound_mode`) plus a phantom `media_player.yamaha_rxv2500`
  appeared in HA but did nothing, and their UI delete buttons were
  disabled. Root cause: retained discovery configs from a pre-1.3
  bring-up experiment still lived on the broker under ad-hoc topics —
  `homeassistant/select/yamaha_input/config`,
  `homeassistant/select/yamaha_sound_mode/config`,
  `homeassistant/media_player/yamaha_rxv2500/config` and
  `.../state` — pointing at command/state topics nobody serves anymore
  (`.../yamaha_input/set`, the JSON state topic). An early check missed
  them because it filtered on the `/rxv2500/` path segment; a full
  retained dump of `homeassistant/#` exposed them. HA keeps entities
  undeletable while a live retained config backs them. Fix: the daemon
  now clears a `LEGACY_DISCOVERY_TOPICS` list with empty retained
  payloads on every discovery publish (`_publish_discovery`), deployed
  2026-10-12 — verified gone from the broker, leaving exactly the 13
  intended configs. If any such ghost ever reappears, add its topic to
  that list.

### Open Questions

1. What is field `0x22`? Stable **per input**, not per feature: re-broadcast
   with the same value across sound-mode, night-mode, speaker and sleep
   commands. Observed `0x05` (PHONO/TUNER/CD-R/MD/TAPE/VCR1), `0x00`
   (CD/DVD/DTV/CBL/SAT/V-AUX), `0x02` (DVR/VCR2). Strong candidate for a
   video/audio terminal assignment — needs the exe's report handler to settle.
2. Confirm the middle input names against the front-panel display (the
   gap-removal mapping gives 0x07=CBL/SAT, 0x09=VCR1, 0x0A=DVR/VCR2).
3. Group `0x36`, `0x3C` (seen with `30 36 01`, `30 3C 01` after power-on)
   — likely zone/power-related bitmaps; values unexplored.
4. Extended-surround values `0x02` / `0x04` unobserved.
5. Sound program indices `17`–`21` (values `0x2E`, `0x2F`, `0x30`–`0x33`,
   `0x35`) exist in the exe's value→index mapper but were never produced by
   any command we swept.
6. Does field `0xB0` ever take nonzero values? (`00 B0 00` seen only on
   power-off.)
7. Dump volume encoding (Phase B, low priority): dumps are decoded with
   the same `−0x27` as event reports — consistent with the panel's
   long-standing −15.0 dB, but the dump frame itself has never been
   panel-verified at arrival. Next spontaneous dump: compare the
   decoded dB against the panel; if off by exactly +0.5 dB the dump
   branch needs its own constant.
8. Is there any inquiry frame that returns volume (or full state) on
   demand? Only the bare-ACK inquiry (`20100`) is verified so far; a
   real inquiry set would remove the last dependence on dumps.
