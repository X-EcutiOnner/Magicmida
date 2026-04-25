unit Dumper;

interface

uses Windows, SysUtils, Classes, Generics.Collections, {$IFNDEF FPC}TlHelp32{$ELSE}JwaTlHelp32{$ENDIF},
     PEInfo, Utils{$IFNDEF FPC}, Math{$ENDIF};

const
  MAX_IAT_SIZE = 5120 * SizeOf(Pointer); // max 5K imports

type
  TExportTable = TDictionary<Pointer, string>;

  TForward = record
    Key: string;
    Value: Pointer;

    constructor Create(const AKey: string; AValue: Pointer);
  end;

  TRemoteModule = record
    Base, EndOff: PByte;
    Name: string;
    ExportTbl: TExportTable;
    Forwards: TList<TForward>;
  end;
  PRemoteModule = ^TRemoteModule;

  TForwardOrigin = record
    SourceModule: PRemoteModule;
    SourceAddress: Pointer;  // address in source module's export table

    constructor Create(ASourceModule: PRemoteModule; ASourceAddress: Pointer);
  end;

  TForwardMap = TObjectDictionary<Pointer, TList<TForwardOrigin>>;

  TImportThunk = class
  public
    Module: PRemoteModule;
    Name: string;
    Addresses: TList<PPointer>;

    constructor Create(RM: PRemoteModule);
    destructor Destroy; override;
  end;

  TDumper = class
  private
    FProcess: TProcessInformation;
    FOEP, FIAT, FImageBase: NativeUInt;
    FForwards: TForwardMap;
    FAllModules: TList<PRemoteModule>;
    FIATImage: PByte;
    FIATImageSize: Cardinal;

    {$IFDEF CPUX86}
    FUsrPath: string;
    FHUsr: HMODULE;

    procedure CollectSpecialUser32Forwards(User32RM: PRemoteModule);
    {$ENDIF}

    procedure GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
    procedure ResolveForwards(M: PRemoteModule);
    procedure TakeModuleSnapshot;
    function GetRemoteModule(const Name: string): PRemoteModule; overload;
    function GetRemoteModule(Base: HMODULE): PRemoteModule; overload;
    function RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
    procedure MakeMemoryReadable(Base, Size: NativeUInt);
  public
    constructor Create(const AProcess: TProcessInformation; AImageBase, AOEP: UIntPtr);
    destructor Destroy; override;

    function Process: TPEHeader;
    procedure DumpToFile(const FileName: string; PE: TPEHeader; IsDLL: Boolean = False);

    function DetermineIATSize(IAT: PByte): UInt32;
    function IsAPIAddress(Address: NativeUInt): Boolean;

    property IAT: NativeUInt read FIAT write FIAT; // Virtual address of IAT in target
  end;

  TDumperDotnet = class
  private
    FProcess: TProcessInformation;
    FImageBase: UIntPtr;
  public
    constructor Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);

    procedure DumpToFile(const FileName: string);
  end;

implementation

const
  ForwardPreferences: array[0..8] of string = (
    'kernel32.dll', // prioritize over kernelbase/ntdll
    'ole32.dll',    // prioritize over combase
    'advapi32.dll', // prioritize over cryptbase
    'netapi32.dll', // prioritize over netutils
    'comdlg32.dll', // prioritize over shlwapi
    'crypt32.dll',  // prioritize over dpapi
    'gdi32.dll',    // prioritize over gdi32full
    'dbghelp.dll',  // prioritize over dbgcore
    'setupapi.dll'  // prioritize over cfgmgr32
  );

function PreferenceScore(const Name: string): Integer;
var
  i: Integer;
begin
  Result := 0;
  for i := Low(ForwardPreferences) to High(ForwardPreferences) do
    if SameText(Name, ForwardPreferences[i]) then
      Inc(Result);
end;

{ TDumper }

constructor TDumper.Create(const AProcess: TProcessInformation; AImageBase, AOEP: UIntPtr);
begin
  FProcess := AProcess;
  FOEP := AOEP;
  FImageBase := AImageBase;

  {$IFDEF CPUX86}
  if Win32MajorVersion > 5 then
  begin
    // user32 has an internal function 'PatchExportTableForwarders' that patches the AddressOfFunctions table.
    FUsrPath := ExtractFilePath(ParamStr(0)) + 'mmusr32.dll';
    CopyFile('C:\Windows\system32\user32.dll', PChar(FUsrPath), False);
    FHUsr := LoadLibraryEx(PChar(FUsrPath), 0, $20) - 2;
  end;
  {$ENDIF}

  FForwards := TForwardMap.Create([doOwnsValues], 512);
end;

destructor TDumper.Destroy;
var
  RM: PRemoteModule;
begin
  FForwards.Free;

  if FAllModules <> nil then
  begin
    for RM in FAllModules do
    begin
      RM.ExportTbl.Free;
      RM.Forwards.Free;
      Dispose(RM);
    end;
    FAllModules.Free;
  end;

  if FIATImage <> nil then
    FreeMem(FIATImage);

  {$IFDEF CPUX86}
  if FHUsr <> 0 then
  begin
    FreeLibrary(FHUsr + 2);
    Windows.DeleteFile(PChar(FUsrPath));
  end;
  {$ENDIF}

  inherited;
end;

{$POINTERMATH ON}

procedure TDumper.DumpToFile(const FileName: string; PE: TPEHeader; IsDLL: Boolean = False);
var
  FS: TFileStream;
  Buf: PByte;
  i: Integer;
  Size, Delta, IATRawOffset: Cardinal;
begin
  FS := TFileStream.Create(FileName, fmCreate);
  try
    Size := PE.DumpSize;
    GetMem(Buf, Size);
    MakeMemoryReadable(FImageBase, Size);
    if not RPM(FImageBase, Buf, Size) then
      raise Exception.CreateFmt('DumpToFile RPM failed (base: %X, size: %X)', [FImageBase, Size]);

    IATRawOffset := FIAT - FImageBase;
    // TrimHugeSections may adjust IATRawOffset depending on what is trimmed.
    Delta := PE.TrimHugeSections(Buf, IATRawOffset);
    Dec(Size, Delta);
    FS.Write(Buf^, Size);
    FreeMem(Buf);

    for i := PE.NTHeaders.FileHeader.NumberOfSections to High(PE.Sections) do
    begin
      FS.Write(PE.Sections[i].Data^, PE.Sections[i].Header.SizeOfRawData);
    end;
    PE.NTHeaders.FileHeader.NumberOfSections := Length(PE.Sections);
    PE.NTHeaders.OptionalHeader.AddressOfEntryPoint := FOEP - FImageBase;

    if IsDLL then
    begin
      PE.NTHeaders.FileHeader.Characteristics := PE.NTHeaders.FileHeader.Characteristics or IMAGE_FILE_DLL;
    end;

    if (PE.NTHeaders.OptionalHeader.DllCharacteristics and $40) <> 0 then
    begin
      Log(ltInfo, 'Executable is ASLR-aware - disabling the flag in the dump');
      PE.NTHeaders.OptionalHeader.DllCharacteristics := PE.NTHeaders.OptionalHeader.DllCharacteristics and not $40;
    end;

    PE.SaveToStream(FS);

    FS.Seek(IATRawOffset, soBeginning);
    FS.Write(FIATImage^, FIATImageSize);
  finally
    FS.Free;
  end;
end;

function TDumper.DetermineIATSize(IAT: PByte): UInt32;
var
  LastValidOffset, i: UInt32;
begin
  LastValidOffset := 0;
  i := 0;
  while (i < MAX_IAT_SIZE) and ((LastValidOffset = 0) or (i < LastValidOffset + $100)) do
  begin
    if IsAPIAddress(PNativeUInt(IAT + i)^) then
      LastValidOffset := i;

    Inc(i, SizeOf(Pointer));
  end;

  Result := LastValidOffset + SizeOf(Pointer);
end;

type
  TResolutionCandidate = record
    Address: Pointer;      // The pointer to use for export lookup
    Module: PRemoteModule;
  end;

  TIATSlot = record
    Candidates: TList<TResolutionCandidate>; // All valid resolutions
    ChosenCandidate: Integer;                // Index into Candidates (-1 = unresolved)
    IsZero: Boolean;
  end;

function TDumper.Process: TPEHeader;
var
  IAT: PByte;
  i, j, k: Integer;
  IATSize, Diff: Cardinal;
  PE: TPEHeader;
  a: ^PByte;
  Fwd: Pointer;
  Thunks: TList<TImportThunk>;
  Thunk: TImportThunk;
  Found: Boolean;
  RM: PRemoteModule;
  s: AnsiString;
  OrdIndex: Cardinal;
  Section, Strs: PByte;
  Descriptors: PImageImportDescriptor;
  ImportSect: PPESection;

  // --- Pass 1 data ---
  Slots: array of TIATSlot;
  Cand: TResolutionCandidate;
  SlotCount: Integer;
  Origins: TList<TForwardOrigin>;
  Origin: TForwardOrigin;

  // --- Pass 2 data ---
  GroupStart, GroupEnd: Integer;
  ModuleVotes: TDictionary<string, Integer>;
  ModuleName, WinnerName: string;
  WinnerVotes: Integer;
  WinnerRM: PRemoteModule;
begin
  if FIAT = 0 then
    raise Exception.Create('Must set IAT before calling Process()');

  // Read header from memory
  GetMem(Section, $1000);
  RPM(FImageBase, Section, $1000);
  PE := TPEHeader.Create(Section);
  PE.Sanitize;
  FreeMem(Section);

  GetMem(IAT, MAX_IAT_SIZE);
  RPM(FIAT, IAT, MAX_IAT_SIZE);

  IATSize := DetermineIATSize(IAT);
  Log(ltInfo, Format('Determined IAT size: %X', [IATSize]));

  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] do
  begin
    VirtualAddress := FIAT - FImageBase;
    Size := IATSize + SizeOf(Pointer);
  end;

  if FAllModules = nil then
    TakeModuleSnapshot;

  SlotCount := IATSize div SizeOf(Pointer);
  SetLength(Slots, SlotCount);

  // =========================================================
  // PASS 1: Collect all candidates for every IAT slot
  // =========================================================
  a := Pointer(IAT);
  for i := 0 to SlotCount - 1 do
  begin
    Slots[i].ChosenCandidate := -1;
    Slots[i].Candidates := TList<TResolutionCandidate>.Create;
    Slots[i].IsZero := a^ = nil;

    if Slots[i].IsZero then
    begin
      Inc(a);
      Continue;
    end;

    // --- Variant A: no forwarding ---
    Cand.Address := a^;
    Cand.Module := nil;
    for RM in FAllModules do
      if (PByte(Cand.Address) > RM.Base) and (PByte(Cand.Address) < RM.EndOff) then
      begin
        if RM.ExportTbl.ContainsKey(Cand.Address) then
        begin
          Cand.Module := RM;
          Slots[i].Candidates.Add(Cand);
        end;
        Break; // only one module owns this address
      end;

    // --- Variant B: FForwards (e.g. ntdll stub -> kernelbase real) ---
    if FForwards.TryGetValue(a^, Origins) then
      for Origin in Origins do
      begin
        Cand.Address := Origin.SourceAddress;
        Cand.Module := Origin.SourceModule;
        Slots[i].Candidates.Add(Cand);
      end;

    if Slots[i].Candidates.Count = 0 then
      Log(ltInfo, 'IAT slot ' + IntToHex(FIAT + Cardinal(i) * SizeOf(Pointer), 8) +
          ' -> ' + IntToHex(UIntPtr(a^), 8) + ' unresolvable');

    Inc(a);
  end;

  // =========================================================
  // PASS 2: For each zero-delimited group, vote on best module
  //         and pin every slot to a candidate from that module
  // =========================================================
  ModuleVotes := TDictionary<string, Integer>.Create;
  Thunks := TObjectList<TImportThunk>.Create;

  i := 0;
  while i < SlotCount do
  begin
    // Skip zero separators (they just end the current thunk naturally)
    if Slots[i].IsZero then
    begin
      Inc(i);
      Continue;
    end;

    // Find contiguous non-zero run = one raw group
    GroupStart := i;
    GroupEnd := i;
    while (GroupEnd + 1 < SlotCount) and not Slots[GroupEnd + 1].IsZero do
      Inc(GroupEnd);

    // Vote: for each slot in group, each candidate casts one vote for its module
    ModuleVotes.Clear;
    for j := GroupStart to GroupEnd do
    begin
      //Log(ltInfo, Format('Slot %d (%p)', [j, PByte(IAT) + j * SizeOf(Pointer)]));
      for k := 0 to Slots[j].Candidates.Count - 1 do
      begin
        ModuleName := Slots[j].Candidates[k].Module.Name;
        //Log(ltInfo, Format(' - Candidate %s %p', [ModuleName, Slots[j].Candidates[k].ActualPtr]));
        if not ModuleVotes.TryGetValue(ModuleName, WinnerVotes) then
          ModuleVotes.Add(ModuleName, 1)
        else
          ModuleVotes[ModuleName] := WinnerVotes + 1;
      end;
    end;

    // Find the module with the most votes; apply scoring in ambiguous cases
    WinnerName := '';
    WinnerVotes := -1;
    WinnerRM := nil;
    for ModuleName in ModuleVotes.Keys do
    begin
      if (ModuleVotes[ModuleName] > WinnerVotes) or
         ((ModuleVotes[ModuleName] = WinnerVotes) and
          (PreferenceScore(ModuleName) > PreferenceScore(WinnerName))) then
      begin
        WinnerVotes := ModuleVotes[ModuleName];
        WinnerName := ModuleName;
      end;
    end;

    // Pin each slot to the winning module's candidate
    // Build sub-thunks within the group where we CAN resolve to winner;
    // slots that have no candidate for winner are logged as bogus.
    for j := GroupStart to GroupEnd do
    begin
      Found := False;
      for k := 0 to Slots[j].Candidates.Count - 1 do
        if Slots[j].Candidates[k].Module.Name = WinnerName then
        begin
          Slots[j].ChosenCandidate := k;
          if WinnerRM = nil then
            WinnerRM := Slots[j].Candidates[k].Module;
          Found := True;
          Break;
        end;
      if (not Found) and (WinnerName <> '') then
        Log(ltFatal, 'IAT slot ' + IntToHex(FIAT + Cardinal(j) * SizeOf(Pointer), 8) +
            ' has no candidate for winning module ' + WinnerName + ' (bogus entry)');
    end;

    // Now walk the group and build thunks, respecting the chosen candidates.
    // Within a zero-free group we stay in one thunk for the winner module.
    Thunk := nil;
    for j := GroupStart to GroupEnd do
    begin
      if Slots[j].ChosenCandidate < 0 then Continue; // bogus, skip

      if Thunk = nil then
      begin
        Thunk := TImportThunk.Create(WinnerRM);
        Thunk.Name := WinnerName;
        Thunks.Add(Thunk);
      end;

      // Write the resolved pointer back into the IAT image
      Cand := Slots[j].Candidates[Slots[j].ChosenCandidate];
      PPointer(PByte(IAT) + j * SizeOf(Pointer))^ := Cand.Address;
      Thunk.Addresses.Add(PPointer(PByte(IAT) + j * SizeOf(Pointer)));
    end;

    i := GroupEnd + 1;
  end;
  ModuleVotes.Free;

  ImportSect := PE.CreateSection('.import', $1000);

  Section := AllocMem(ImportSect.Header.SizeOfRawData);
  Pointer(Descriptors) := Section; // Map the Descriptors array to the start of the section
  Strs := Section + (Thunks.Count + 1) * SizeOf(TImageImportDescriptor); // Last descriptor is empty

  i := 0;
  for Thunk in Thunks do
  begin
    Descriptors[i].FirstThunk := (FIAT - FImageBase) + UIntPtr(Thunk.Addresses.First) - UIntPtr(IAT);
    Descriptors[i].Name := PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - Section));
    Inc(i);
    s := AnsiString(Thunk.Name);
    Move(s[1], Strs^, Length(s));
    Inc(Strs, Length(s) + 1);
    RM := Thunk.Module;
    Log(ltInfo, 'Thunk ' + Thunk.Name + ' - first import: ' + RM.ExportTbl[Thunk.Addresses.First^]);
    for j := 0 to Thunk.Addresses.Count - 1 do
    begin
      s := AnsiString(RM.ExportTbl[Thunk.Addresses[j]^]);
      if s[1] = '#' then
      begin
        OrdIndex := StrToInt(Copy(string(s), 2, 5));
        Thunk.Addresses[j]^ := Pointer(IMAGE_ORDINAL_FLAG or OrdIndex);
        Continue;
      end;

      Inc(Strs, 2); // Hint
      // Set the address in the IAT to this string entry
      Thunk.Addresses[j]^ := Pointer(PE.ConvertOffsetToRVAVector(ImportSect.Header.PointerToRawData + Cardinal(Strs - 2 - Section)));
      Move(s[1], Strs^, Length(s));
      Inc(Strs, Length(s) + 1);

      if Strs > Section + ImportSect.Header.SizeOfRawData - $100 then
      begin
        Inc(ImportSect.Header.SizeOfRawData, $1000);
        Inc(ImportSect.Header.Misc.VirtualSize, $1000);
        Inc(PE.NTHeaders.OptionalHeader.SizeOfImage, $1000);
        Diff := Strs - Section;
        ReallocMem(Section, ImportSect.Header.SizeOfRawData);
        FillChar((Section + ImportSect.Header.SizeOfRawData - $1000)^, $1000, 0);
        Strs := Section + Diff;
        Pointer(Descriptors) := Section;
        //Log(ltInfo, 'Increased import section size to ' + IntToHex(ImportSect.Header.SizeOfRawData, 4));
      end;
    end;
  end;

  ImportSect.Data := Section;
  with PE.NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] do
  begin
    VirtualAddress := ImportSect.Header.VirtualAddress;
    Size := Thunks.Count * SizeOf(TImageImportDescriptor);
  end;

  Thunks.Free;

  FIATImage := IAT;
  FIATImageSize := IATSize;

  Result := PE;
end;

procedure TDumper.GatherModuleExportsFromRemoteProcess(M: PRemoteModule);
var
  Head: PByte;
  ExpDataDir: TImageDataDirectory;
  Exp: PImageExportDirectory;
  Off: PByte;
  a, n: PCardinal;
  o: PWord;
  i: Integer;
  Named: array of Boolean;
  FuncIndex: Cardinal;
  Fwd: PAnsiChar;
begin
  GetMem(Head, $1000);
  try
    RPM(NativeUInt(M.Base), Head, $1000);
    ExpDataDir := PImageNtHeaders(Head + PImageDosHeader(Head)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExpDataDir.VirtualAddress = 0) or (ExpDataDir.Size < SizeOf(TImageExportDirectory)) then
      Exit;

    GetMem(Exp, ExpDataDir.Size);
    RPM(NativeUInt(M.Base + ExpDataDir.VirtualAddress), Exp, ExpDataDir.Size);
    Off := PByte(Exp) - ExpDataDir.VirtualAddress;
  finally
    FreeMem(Head);
  end;

  Pointer(a) := Off + Exp.AddressOfFunctions;
  Pointer(n) := Off + Exp.AddressOfNames;
  Pointer(o) := Off + Exp.AddressOfNameOrdinals;

  SetLength(Named, Exp.NumberOfFunctions);
  FillChar(Named[0], Length(Named) * SizeOf(Boolean), 0);

  for i := 0 to Exp.NumberOfNames - 1 do
  begin
    FuncIndex := o[i];
    Named[FuncIndex] := True;
    M.ExportTbl.AddOrSetValue(M.Base + a[FuncIndex], string(AnsiString(PAnsiChar(Off + n[i]))));
  end;
  for i := 0 to Exp.NumberOfFunctions - 1 do
  begin
    // Add ordinals
    if not Named[i] then
    begin
      FuncIndex := Exp.Base + UInt32(i);
      M.ExportTbl.AddOrSetValue(M.Base + a[i], '#' + IntToStr(FuncIndex));
    end;

    // Check if entry is forward
    if (a[i] > ExpDataDir.VirtualAddress) and (a[i] < ExpDataDir.VirtualAddress + ExpDataDir.Size) then
    begin
      Fwd := PAnsiChar(Off + a[i]); // e.g. 'NTDLL.RtlAllocateHeap'
      if Pos(AnsiString('.#'), Fwd) = 0 then
      begin
        M.Forwards.Add(TForward.Create(string(AnsiString(Fwd)), M.Base + a[i]));
      end;
    end;
  end;

  FreeMem(Exp);
end;

{$IFDEF CPUX86}
procedure TDumper.CollectSpecialUser32Forwards(User32RM: PRemoteModule);
var
  ModScan: PByte;
  ExpDataDir: TImageDataDirectory;
  ExpDir: PImageExportDirectory;
  i: Integer;
  a: PCardinal;
  Fwd: PAnsiChar;
begin
  // Scan specially loaded user32 copy, because forwards are patched out in normally loaded user32 images.
  ModScan := Pointer(FHUsr);
  ExpDataDir := PImageNTHeaders(ModScan + PImageDosHeader(ModScan)._lfanew).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  ExpDir := Pointer(ModScan + ExpDataDir.VirtualAddress);

  a := PCardinal(ModScan + ExpDir.AddressOfFunctions);
  for i := 0 to ExpDir.NumberOfFunctions - 1 do
  begin
    Fwd := PAnsiChar(ModScan + a^);
    if (PByte(Fwd) > ModScan + ExpDataDir.VirtualAddress) and (PByte(Fwd) < ModScan + ExpDataDir.VirtualAddress + ExpDataDir.Size) and (Pos(AnsiString('.#'), Fwd) = 0) then
    begin
      User32RM.Forwards.Add(TForward.Create(string(AnsiString(Fwd)), nil));
    end;
    Inc(a);
  end;
end;
{$ENDIF}

procedure TDumper.ResolveForwards(M: PRemoteModule);
var
  Fwd: TForward;
  DotPos: Integer;
  ForwardModName, ForwardAPIName: string;
  ForwardMod: PRemoteModule;
  APISetResolved: HMODULE;
  Exprt: TPair<Pointer, string>;
  ProcAddr, FwdValue: Pointer;
begin
  for Fwd in M.Forwards do
  begin
    //Log(ltInfo, M.Name + ' --> ' + Fwd.Key);

    DotPos := Pos('.', Fwd.Key);
    ForwardModName := Copy(Fwd.Key, 1, DotPos - 1);
    if Pos('-ms-win-', ForwardModName) = 4 then // api-ms-win, ext-ms-win
    begin
      // Take a shortcut by resolving this locally.
      APISetResolved := GetModuleHandle(PChar(ForwardModName));
      if APISetResolved <> 0 then
        ForwardMod := GetRemoteModule(APISetResolved)
      else
        ForwardMod := nil;
    end
    else
      ForwardMod := GetRemoteModule(ForwardModName + '.dll');

    if ForwardMod <> nil then
    begin
      ForwardAPIName := Copy(Fwd.Key, DotPos + 1, 50);
      ProcAddr := nil;
      for Exprt in ForwardMod.ExportTbl do
        if Exprt.Value = ForwardAPIName then
        begin
          ProcAddr := Exprt.Key;
          Break;
        end;

      if ProcAddr <> nil then
      begin
        if not FForwards.ContainsKey(ProcAddr) then
          FForwards.Add(ProcAddr, TList<TForwardOrigin>.Create);
        FwdValue := Fwd.Value;
        {$IFDEF CPUX86}
        if M.Name = 'user32.dll' then
          FwdValue := ProcAddr; // user32 ExportTbl has the patched (resolved) values
        {$ENDIF}
        FForwards[ProcAddr].Add(TForwardOrigin.Create(M, FwdValue));
      end;
      //Log(ltInfo, Format('%s @ %p', [ForwardAPIName, ProcAddr]));
    end
    //else
    //  Log(ltFatal, Format('Forward target not loaded: %s', [ForwardModName]));
  end;
end;

function TDumper.GetRemoteModule(Base: HMODULE): PRemoteModule;
begin
  for Result in FAllModules do
    if HMODULE(Result.Base) = Base then
      Exit;
  Result := nil;
end;

function TDumper.GetRemoteModule(const Name: string): PRemoteModule;
begin
  for Result in FAllModules do
    if Result.Name = LowerCase(Name) then
      Exit;
  Result := nil;
end;

function TDumper.IsAPIAddress(Address: NativeUInt): Boolean;
var
  RM: PRemoteModule;
begin
  if FAllModules = nil then
    TakeModuleSnapshot;

  for RM in FAllModules do
    if (Address >= NativeUInt(RM.Base)) and (Address < NativeUInt(RM.EndOff)) then
      Exit(RM.ExportTbl.ContainsKey(Pointer(Address)));

  Result := False;
end;

procedure TDumper.TakeModuleSnapshot;
var
  hSnap: THandle;
  ME: TModuleEntry32;
  RM: PRemoteModule;
begin
  FAllModules := TList<PRemoteModule>.Create;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, FProcess.dwProcessId);
  ME.dwSize := SizeOf(TModuleEntry32);
  if not Module32First(hSnap, ME) then
    raise Exception.Create('Module32First');
  repeat
    if ME.hModule <> FImageBase then
    begin
      //Log(ltInfo, IntToHex(ME.hModule, 8) + ' : ' + IntToHex(ME.modBaseSize, 4) + ' : ' + string(ME.szModule));
      New(RM);
      RM.Base := ME.modBaseAddr;
      RM.EndOff := ME.modBaseAddr + ME.modBaseSize;
      RM.Name := LowerCase(ME.szModule);
      RM.ExportTbl := TExportTable.Create;
      RM.Forwards := TList<TForward>.Create;
      GatherModuleExportsFromRemoteProcess(RM);
      {$IFDEF CPUX86}
      if (RM.Name = 'user32.dll') and (FHUsr <> 0) then
        CollectSpecialUser32Forwards(RM);
      {$ENDIF}
      FAllModules.Add(RM);
    end;
  until not Module32Next(hSnap, ME);
  CloseHandle(hSnap);

  for RM in FAllModules do
    ResolveForwards(RM);
end;

function TDumper.RPM(Address: NativeUInt; Buf: Pointer; BufSize: NativeUInt): Boolean;
begin
  Result := ReadProcessMemory(FProcess.hProcess, Pointer(Address), Buf, BufSize, BufSize);
  if not Result then
    Log(ltFatal, 'RPM failed');
end;

procedure TDumper.MakeMemoryReadable(Base, Size: NativeUInt);
var
  mbi: MEMORY_BASIC_INFORMATION;
  Addr: NativeUInt;
  EndAddr: NativeUInt;
  BytesReturned: SIZE_T;
  OldProtect: DWORD;
begin
  Addr := Base;
  EndAddr := Addr + Size;

  while Addr < EndAddr do
  begin
    BytesReturned := VirtualQueryEx(FProcess.hProcess, Pointer(Addr), mbi, SizeOf(mbi));

    if BytesReturned = 0 then
      Break;

    if (mbi.State = MEM_COMMIT) and (mbi.Protect = PAGE_NOACCESS) then
      VirtualProtectEx(FProcess.hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_READONLY, @OldProtect);

    Addr := NativeUInt(mbi.BaseAddress) + mbi.RegionSize;
  end;
end;

{ TDumperDotnet }

constructor TDumperDotnet.Create(const AProcess: TProcessInformation; AImageBase: UIntPtr);
begin
  FProcess := AProcess;
  FImageBase := AImageBase;
end;

procedure TDumperDotnet.DumpToFile(const FileName: string);
var
  FS: TFileStream;
  Header: array[0..$FFF] of Byte;
  PE: TPEHeader;
  Buf, Ptr: PByte;
  Size, PhysicalSize, ImageSize, Done: DWORD;
  NumRead: UIntPtr;
  Mbi: TMemoryBasicInformation;
begin
  // Dumping Themida .NET binaries appears to be quite simple because
  // no special imports processing is required.
  NumRead := 0;
  if not ReadProcessMemory(FProcess.hProcess, Pointer(FImageBase), @Header, $1000, NumRead) then
    raise Exception.Create('DumpToFile header RPM failed');

  PE := TPEHeader.Create(@Header);
  with PE.Sections[PE.NTHeaders.FileHeader.NumberOfSections - 1] do
    Size := Header.VirtualAddress + Header.Misc.VirtualSize;

  FS := TFileStream.Create(FileName, fmCreate);
  GetMem(Buf, Size);
  try
    PhysicalSize := Size;
    PE.FileAlign(PhysicalSize);
    ImageSize := PhysicalSize;
    PE.SectionAlign(ImageSize);
    PE.NTHeaders.OptionalHeader.SizeOfImage := ImageSize;
    PE.Sections[0].Rename('.text');

    Log(ltInfo, Format('Output has %d sections, determined size to be 0x%X', [PE.NTHeaders.FileHeader.NumberOfSections, Size]));

    Ptr := PByte(FImageBase);
    Done := 0;
    Mbi.RegionSize := $1000;
    while Done < Size do
    begin
      if VirtualQueryEx(FProcess.hProcess, Ptr, Mbi, SizeOf(Mbi)) = 0 then
        raise Exception.CreateFmt('VirtualQueryEx failed at %p', [Ptr]);
      if Mbi.RegionSize = 0 then
        raise Exception.CreateFmt('VirtualQueryEx returned a zero region at %p', [Ptr]); // Idk if/why it would do this but we wouldn't make any progress then

      if Mbi.State = MEM_COMMIT then
      begin
        NumRead := 0;
        if not ReadProcessMemory(FProcess.hProcess, Ptr, Buf + Done, Min(Size - Done, Mbi.RegionSize), NumRead) then
          raise Exception.Create('DumpToFile RPM failed');
      end
      else if Mbi.State = MEM_RESERVE then
      begin
        // We could mess with the section addresses and leave this chunk out of the physical file, but eh...
        FillChar((Buf + Done)^, Min(Size - Done, Mbi.RegionSize), 0);
      end
      else
        raise Exception.CreateFmt('Got unexpected region state %X at %p', [Mbi.State, Ptr]);

      Inc(Done, Mbi.RegionSize);
      Inc(Ptr, Mbi.RegionSize);
    end;

    FS.Write(Buf^, Size);
    if Size < PhysicalSize then
    begin
      // Pad to file alignment
      ReallocMem(Buf, PhysicalSize - Size);
      FillChar(Buf^, PhysicalSize - Size, 0);
      FS.Write(Buf^, PhysicalSize - Size);
    end;

    PE.SaveToStream(FS);
  finally
    FreeMem(Buf);
    PE.Free;
    FS.Free;
  end;
end;

{ TImportThunk }

constructor TImportThunk.Create(RM: PRemoteModule);
begin
  Module := RM;
  Name := RM.Name;
  Addresses := TList<PPointer>.Create;
end;

destructor TImportThunk.Destroy;
begin
  Addresses.Free;

  inherited;
end;

{ TForward }

constructor TForward.Create(const AKey: string; AValue: Pointer);
begin
  Key := AKey;
  Value := AValue;
end;

{ TForwardOrigin }

constructor TForwardOrigin.Create(ASourceModule: PRemoteModule; ASourceAddress: Pointer);
begin
  SourceModule := ASourceModule;
  SourceAddress := ASourceAddress;
end;

end.
