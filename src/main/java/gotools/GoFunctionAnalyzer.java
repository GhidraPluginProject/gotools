package gotools;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class GoFunctionAnalyzer extends GoTypesAnalyzer {

  private Map<Long, Long> funcmap = new HashMap<>();

  public GoFunctionAnalyzer() {
    super("Go Function Analyzer", "Recovers function names in go binaries.", AnalyzerType.BYTE_ANALYZER);
    setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
  }

  @Override
  public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
    MemoryBlock gopcln;
    try {
      gopcln = getGopclntab(p);
    } catch (NotFoundException e) {
      log.appendException(e);
      throw new CancelledException("gopclntab not found");
    }
    try {
      recoverGoFunctions(p, monitor, log, gopcln);
    } catch (MemoryAccessException e) {
      log.appendException(e);
      return false;
    }
    return true;
  }

  private void recoverGoFunctions(Program p, TaskMonitor m, MessageLog log, MemoryBlock gopc)
      throws MemoryAccessException {
    // TODO this only works for 64bit binaries
    long pointerSize = 8;
    Address a = gopc.getStart();
    int goVersionMagic = p.getMemory().getInt(a);
    try {
      createData(p, a, new IntegerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);

    // https://github.com/golang/go/blob/release-branch.go1.16/src/debug/gosym/pclntab.go#L169
    if (goVersionMagic == 0xfffffffb) {
      getInformation12(p, m, log, gopc, a, pointerSize);
    } else {
      getInformation116(p, m, log, gopc, a, pointerSize);
    }
  }

  private void getInformation12(Program p, TaskMonitor m, MessageLog log, MemoryBlock gopc, Address a, long pointerSize)
      throws MemoryAccessException {
    // skip unimportant header
    long size = p.getMemory().getLong(a);
    a = a.add(pointerSize);
    for (int i = 0; i < size; i++) {
      long funcOffset = p.getMemory().getLong(a); // TODO use createDword
      a = a.add(pointerSize);
      long nameOffset = p.getMemory().getLong(a); // TODO use createDword
      a = a.add(pointerSize);
      Address nameGoStrPointer = gopc.getStart().add(nameOffset + pointerSize);
      Address name = gopc.getStart().add(p.getMemory().getInt(nameGoStrPointer));
      Data d;
      try {
        // TODO we probably know the lenght of the string
        d = createData(p, name, new StringDataType());
      } catch (Exception e) {
        log.appendException(e);
        continue;
      }
      Address funcPointer = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcOffset);
      Function f = p.getFunctionManager().getFunctionAt(funcPointer);
      String functionName = (String) (d.getValue());
      if (functionName.startsWith("type..") || functionName.endsWith(".")) {
        // TODO what to do with it?
        p.getListing().setComment(funcPointer, CodeUnit.EOL_COMMENT, functionName);
        continue;
      }
      if (gopc.contains(funcPointer)) {
        log.appendMsg(String.format("skipped %s because it is in the section", functionName));
        continue;
      }
      if (f == null) {
        CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, funcPointer, null, SourceType.ANALYSIS);
        if (!cmd.applyTo(p, m)) {
          log.appendMsg(
              String.format("Unable to create function at %s, (expected %s)\n", d.getAddress(), d.getValue()));
        }
        continue;
      } else if (f.getName().equals(functionName)) {
        continue;
      }
      try {
        f.setName(functionName, SourceType.ANALYSIS);
        funcmap.put(nameOffset, funcPointer.getOffset());
      } catch (DuplicateNameException | InvalidInputException e) {
        log.appendException(e);
        continue;
      }
    }
  }

  private void getInformation116(Program p, TaskMonitor m, MessageLog log, MemoryBlock gopc, Address a,
      long pointerSize) throws MemoryAccessException {
    Address funcDataTable, currentFuncTable;
    long size = p.getMemory().getLong(a);
    a = a.add(pointerSize * 2);
    long funcNameTableOffset = p.getMemory().getLong(a);
    a = a.add(pointerSize * 4);
    long funcDataTableOffset = p.getMemory().getLong(a);
    funcDataTable = gopc.getStart().add(funcDataTableOffset);
    currentFuncTable = gopc.getStart().add(funcDataTableOffset);

    for (int i = 0; i < size; i++) {
      long funcEntryPoint, funcDataOffset;
      int funcNameOffset;
      try {
        funcEntryPoint = p.getMemory().getLong(currentFuncTable);
        currentFuncTable = currentFuncTable.add(pointerSize);

        funcDataOffset = p.getMemory().getLong(currentFuncTable);
        currentFuncTable = currentFuncTable.add(pointerSize);

        funcNameOffset = p.getMemory().getInt(funcDataTable.add(funcDataOffset + pointerSize));
      } catch (Exception e) {
        log.appendException(e);
        continue;
      }

      Address namePointer = gopc.getStart().add(funcNameTableOffset + funcNameOffset);
      Data d;
      try {
        d = createData(p, namePointer, new StringDataType());
        p.getListing().setComment(namePointer, CodeUnit.EOL_COMMENT, d.getValue().toString());
      } catch (Exception e) {
        log.appendException(e);
        continue;
      }
      Address funcPointer = p.getAddressFactory().getDefaultAddressSpace().getAddress(funcEntryPoint);
      Function f = p.getFunctionManager().getFunctionAt(funcPointer);
      String functionName = (String) (d.getValue());
      if (functionName.startsWith("type..") || functionName.endsWith(".")) {
        // TODO what to do with it?
        p.getListing().setComment(funcPointer, CodeUnit.EOL_COMMENT, functionName);
        continue;
      }
      if (gopc.contains(funcPointer)) {
        log.appendMsg(String.format("skipped %s because it is in the section", functionName));
        continue;
      }
      if (f == null) {
        CreateFunctionCmd cmd = new CreateFunctionCmd(functionName, funcPointer, null, SourceType.ANALYSIS);
        if (!cmd.applyTo(p, m)) {
          log.appendMsg(
              String.format("Unable to create function at %s, (expected %s)\n", d.getAddress(), d.getValue()));
        }
        continue;
      } else if (f.getName().equals(functionName)) {
        funcmap.put((long) funcNameOffset, funcPointer.getOffset());
        continue;
      }
      try {
        f.setName(functionName, SourceType.ANALYSIS);
        funcmap.put((long) funcNameOffset, funcPointer.getOffset());
      } catch (DuplicateNameException | InvalidInputException e) {
        log.appendException(e);
        continue;
      }
    }
  }
}