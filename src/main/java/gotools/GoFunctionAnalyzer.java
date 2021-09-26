package gotools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DoubleComplexDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatComplexDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

public class GoFunctionAnalyzer extends AnalyzerBase {
  private final String[] TYPE_KINDS = new String[] { "Invalid Kind", "Bool", "Int", "Int8", "Int16", "Int32", "Int64",
      "Uint", "Uint8", "Uint16", "Uint32", "Uint64", "Uintptr", "Float32", "Float64", "Complex64", "Complex128",
      "Array", "Chan", "Func", "Interface", "Map", "Ptr", "Slice", "String", "Struct", "UnsafePointer" };
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
    try {
      analyzeModuleData(p, m, log);
    } catch (Exception e) {
      log.appendException(e);
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

  private void analyzeModuleData(Program p, TaskMonitor m, MessageLog log) {
    // TODO only works for 64 bit binaries
    log.appendMsg(funcmap.size() + " functions found");
    int pointerSize = 8;
    FlatProgramAPI flatapi = new FlatProgramAPI(p, m);
    try {
      Address gopcln = getGopclntab(p).getStart();
      long l = gopcln.getOffset();
      byte[] b = new byte[] { (byte) l, (byte) (l >> 8), (byte) (l >> 16), (byte) (l >> 24), (byte) (l >> 32),
          (byte) (l >> 40), (byte) (l >> 48), (byte) (l >> 56) };
      Address moduleData = flatapi.find(gopcln, b);
      int cnt = 0;
      // avoid infinite loop
      while (moduleData.getOffset() != 0 && cnt < 100) {
        cnt += 1;
        try {
          long[] types = setModuleData(p, moduleData, flatapi, pointerSize, log);
          moduleData = flatapi.toAddr(types[3]);
          Address typeBase = flatapi.toAddr(types[0]);
          Address typelinkAddr = flatapi.toAddr(types[1]);
          long length = types[2];
          for (int i = 0; i < length; i++) {
            try {
              flatapi.clearListing(typelinkAddr);
              Data data = flatapi.createData(typelinkAddr, new IntegerDataType());
              long offset = ((Scalar) data.getValue()).getValue();
              Address typeAddress = flatapi.toAddr(typeBase.getOffset() + offset);
              long[] resp = setRType(p, typeAddress, flatapi, pointerSize, log);
              int idx = (int) resp[0];
              typeAddress = flatapi.toAddr(resp[1]);
              long nameoff = resp[2];
              idx = idx & ((1 << 5) - 1); // mask kind
              if (idx > 27) {
                idx = 0;
              }
              String kind = TYPE_KINDS[idx];
              typelinkAddr = typelinkAddr.add(4);
              p.getListing().setComment(typeAddress, CodeUnit.EOL_COMMENT, "kind: " + kind);
              switch (kind) {
                case "Bool":
                  flatapi.createData(typeAddress, new BooleanDataType());
                  break;
                case "Int":
                  flatapi.createData(typeAddress, new IntegerDataType());
                  break;
                case "Int8":
                  flatapi.createData(typeAddress, new ByteDataType());
                  break;
                case "Int16":
                  flatapi.createData(typeAddress, new ShortDataType());
                  break;
                case "Int32":
                  flatapi.createData(typeAddress, new IntegerDataType());
                  break;
                case "Int64":
                  flatapi.createData(typeAddress, new LongDataType());
                  break;
                case "Uint":
                  flatapi.createData(typeAddress, new UnsignedIntegerDataType());
                  break;
                case "Uint8":
                  flatapi.createData(typeAddress, new UnsignedCharDataType());
                  break;
                case "Uint16":
                  flatapi.createData(typeAddress, new UnsignedShortDataType());
                  break;
                case "Uint32":
                  flatapi.createData(typeAddress, new UnsignedIntegerDataType());
                  break;
                case "Uint64":
                  flatapi.createData(typeAddress, new UnsignedLongDataType());
                  break;
                case "Uintptr": // TODO: only 64bit
                  flatapi.createData(typeAddress, new UnsignedLongDataType());
                  break;
                case "Float32":
                  flatapi.createData(typeAddress, new FloatDataType());
                  break;
                case "Float64":
                  flatapi.createData(typeAddress, new DoubleDataType());
                  break;
                case "Complex64":
                  flatapi.createData(typeAddress, new FloatComplexDataType());
                  break;
                case "Complex128":
                  flatapi.createData(typeAddress, new DoubleComplexDataType());
                  break;
                case "Array":
                  setArrayType(typeAddress, flatapi, pointerSize);
                  break;
                case "Chan":
                  setChanType(typeAddress, flatapi, pointerSize);
                  break;
                case "Func":
                  short[] funcArgmentAndReturn = setFuncType(typeAddress, flatapi, pointerSize);
                  p.getListing().setComment(typeAddress, CodeUnit.EOL_COMMENT,
                      "in:" + funcArgmentAndReturn[0] + " out:" + funcArgmentAndReturn[1]);
                  Long addr = funcmap.get(nameoff);
                  if (addr == null) {
                    log.appendMsg("Unable to find function for " + nameoff);
                    break;
                    // TODO: what should we do here?
                  }
                  Address funcAddr = flatapi.toAddr(funcmap.get(nameoff));
                  Function f = p.getFunctionManager().getFunctionAt(funcAddr);
                  StructureDataType s = new StructureDataType(String.format("ret_%d", f.getSymbol().getID()), 0);
                  for (int c = 0; c < funcArgmentAndReturn[1]; c++) {
                    s.add(new Undefined8DataType());
                    // TODO: search argment type and set stackoffset/register belong to calling
                    // convention
                  }
                  // The type is set to imported because otherwise we cannot overwrite it
                  f.setReturn(s, new VariableStorage(p, 0, s.getLength()), SourceType.IMPORTED);
                  List<Variable> args = new ArrayList<Variable>();
                  for (int c = 0; c < funcArgmentAndReturn[0]; c++) {
                    args.add(new ParameterImpl(String.format("arg_%d", c), new Undefined8DataType(), 0, p));
                  }
                  f.replaceParameters(args, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.IMPORTED);
                  break;
                case "Interface":
                  setInterfaceType(typeAddress, flatapi, pointerSize);
                  break;
                case "Map":
                  setMapType(typeAddress, flatapi, pointerSize);
                  break;
                case "Ptr":
                  setPtrType(typeAddress, flatapi, pointerSize);
                  break;
                case "Slice":
                  setSliceType(typeAddress, flatapi, pointerSize);
                  break;
                case "String":
                  flatapi.clearListing(typeAddress);
                  flatapi.createData(typeAddress, new PointerDataType());
                  typeAddress = typeAddress.add(pointerSize);
                  flatapi.clearListing(typeAddress);
                  flatapi.createData(typeAddress, new IntegerDataType());
                  break;
                case "Struct":
                  setStructType(typeAddress, flatapi, pointerSize);
                  break;
                case "UnsafePointer":
                  flatapi.createData(typeAddress, new PointerDataType());
                default:
                  break;
              }// TODO other types

            } catch (Exception e) {
              log.appendException(e);
            }
          }
        } catch (Exception e) {
          log.appendException(e);
          continue;
        }

      }
    } catch (Exception e) {
      log.appendException(e);
    }
  }

  /*
  @formatter:off
  type arrayType struct {
    rtype
    elem  *rtype // array element type
    slice *rtype // slice type
    len   uintptr
  }
  @formatter:on
  */
  private long[] setArrayType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[3];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[1] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new LongDataType());
    ret[2] = ((Scalar) data.getValue()).getValue();
    return ret;
  }

  /*
  @formatter:off
  type chanType struct {
    rtype
    elem *rtype  // channel element type
    dir  uintptr // channel direction (ChanDir)
  }
  @formatter:on
  */
  private long[] setChanType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[3];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[2] = ((Address) data.getValue()).getOffset();
    return ret;
  }

  /*
  @formatter:off
  type funcType struct {
    rtype // embadded
    inCount  uint16
    outCount uint16 // top bit is set if last input parameter is ...
  }
  @formatter:on
  */
  private short[] setFuncType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    Data data = flatapi.createData(a, new ShortDataType());

    short inCount = (short) ((Scalar) data.getValue()).getValue();
    a = a.add(2);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new ShortDataType());

    short outCount = (short) ((Scalar) data.getValue()).getValue();
    a = a.add(2);
    short[] ret = new short[2];
    ret[0] = inCount;
    ret[1] = outCount;
    return ret;
  }

  /*
  @formatter:off
  type imethod struct {
    name nameOff // name of method
    typ  typeOff // .(*FuncType) underneath
  }
  
  */
  // private long[] setIMethod(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
  //   flatapi.clearListing(a);
  //   long[] ret = new long[2];
  //   Data data = flatapi.createData(a, new ShortDataType());
  //   ret[0] = ((Scalar) data.getValue()).getValue();
  //   a = a.add(pointerSize);
  //   data = flatapi.createData(a, new ShortDataType());
  //   ret[1] = ((Scalar) data.getValue()).getValue();
  //   return ret;
  // }
  // @formatter:on

  /*
  @formatter:off
  type interfaceType struct {
    rtype
    pkgPath name      // import path
    methods []imethod // sorted by hash
  }
  @formatter:on
  */
  private long[] setInterfaceType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[2];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[1] = ((Address) data.getValue()).getOffset();
    return ret;
  }

  /*
  @formatter:off
  type mapType struct {
    rtype
    key    *rtype // map key type
    elem   *rtype // map element (value) type
    bucket *rtype // internal bucket structure
    // function for hashing keys (ptr to key, seed) -> hash
    hasher     func(unsafe.Pointer, uintptr) uintptr
    keysize    uint8  // size of key slot
    valuesize  uint8  // size of value slot
    bucketsize uint16 // size of bucket
    flags      uint32
  }
  @formatter:on
  */
  private long[] setMapType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[3];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[1] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[2] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    flatapi.createData(a, new LongDataType());
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    flatapi.createData(a, new ByteDataType());
    a = a.add(1);
    flatapi.clearListing(a);
    flatapi.createData(a, new ByteDataType());
    a = a.add(1);
    flatapi.clearListing(a);
    flatapi.createData(a, new ShortDataType());
    a = a.add(2);
    flatapi.clearListing(a);
    flatapi.createData(a, new IntegerDataType());
    a = a.add(4);
    return ret;
  }

  /*
  @formatter:off
  type ptrType struct {
    rtype
    elem *rtype // pointer element (pointed at) type
  }
  @formatter:on
  */
  private long[] setPtrType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[1];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    return ret;
  }

  /*
  @formatter:off
  type sliceType struct {
    rtype
    elem *rtype // slice element type
  }
  @formatter:on
  */
  private long[] setSliceType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[1];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    return ret;
  }

  /*
  @formatter:off
  type structField struct {
    name        name    // name is always non-empty
    typ         *rtype  // type of field
    offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
  }
  */
  // private long[] setStructField(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
  //   flatapi.clearListing(a);
  //   long[] ret = new long[2];
  //   Data data = flatapi.createData(a, new PointerDataType());
  //   ret[0] = ((Address) data.getValue()).getOffset();
  //   a = a.add(pointerSize);
  //   data = flatapi.createData(a, new LongDataType());
  //   ret[1] = ((Scalar) data.getValue()).getValue();
  //   return ret;
  // }
  // @formatter:on

  /*
  @formatter:off
  type structType struct {
    rtype
    pkgPath name
    fields  []structField // sorted by offset
  }
  @formatter:on
  */
  private long[] setStructType(Address a, FlatProgramAPI flatapi, int pointerSize) throws Exception {
    flatapi.clearListing(a);
    long[] ret = new long[2];
    Data data = flatapi.createData(a, new PointerDataType());
    ret[0] = ((Address) data.getValue()).getOffset();
    a = a.add(pointerSize);
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    ret[1] = ((Address) data.getValue()).getOffset();
    return ret;
  }
  /*
  @formatter:off
  type rtype struct {
    size       uintptr
    ptrdata    uintptr // number of bytes in the type that can contain pointers
    hash       uint32  // hash of type; avoids computation in hash tables
    tflag      tflag   // extra type information flags
    align      uint8   // alignment of variable with this type
    fieldAlign uint8   // alignment of struct field with this type
    kind       uint8   // enumeration for C
    // function for comparing objects of this type
    // (ptr to object A, ptr to object B) -> ==?
    equal     func(unsafe.Pointer, unsafe.Pointer) bool
    gcdata    *byte   // garbage collection data
    str       nameOff // string form
    ptrToThis typeOff // type for pointer to this type, may be zero
  }
  @formatter:on
  */

  private long[] setRType(Program p, Address a, FlatProgramAPI flatapi, int pointerSize, MessageLog log)
      throws Exception {
    p.getListing().clearCodeUnits(a, a.add(pointerSize * 6), false);
    // size
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // ptrdata
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // hash
    flatapi.clearListing(a);
    flatapi.createData(a, new IntegerDataType());
    a = a.add(4);
    // tflag
    flatapi.clearListing(a);
    flatapi.createData(a, new ByteDataType());
    a = a.add(1);
    // align
    flatapi.clearListing(a);
    flatapi.createData(a, new ByteDataType());
    a = a.add(1);
    // fieldAlign
    flatapi.clearListing(a);
    flatapi.createData(a, new ByteDataType());
    a = a.add(1);
    // kind
    flatapi.clearListing(a);
    Data data = flatapi.createData(a, new ByteDataType());
    long kind = ((Scalar) data.getValue()).getValue();
    a = a.add(1);
    // equal
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // gcdata
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // str
    flatapi.clearListing(a);
    data = flatapi.createData(a, new IntegerDataType());
    long nameoff = ((Scalar) data.getValue()).getValue();
    a = a.add(4);
    // ptrToThis
    flatapi.clearListing(a);
    flatapi.createData(a, new IntegerDataType());
    a = a.add(4);
    return new long[] { kind, a.getOffset(), nameoff };
  }

  /*
  @formatter:off
  type moduledata struct {
    pcHeader     *pcHeader 1
    funcnametab  []byte 3
    cutab        []uint32 3
    filetab      []byte 3
    pctab        []byte 3
    pclntable    []byte 3
    ftab         []functab 3
    findfunctab  uintptr 1
    minpc, maxpc uintptr 2

    text, etext           uintptr 2
    noptrdata, enoptrdata uintptr 2
    data, edata           uintptr 2
    bss, ebss             uintptr 2 
    noptrbss, enoptrbss   uintptr 2
    end, gcdata, gcbss    uintptr 3  
    types, etypes         uintptr 2

    textsectmap []textsect 3
    typelinks   []int32 // 3 offsets from types
    itablinks   []*itab 3

    ptab []ptabEntry 3

    pluginpath string 2
    pkghashes  []modulehash 3

    modulename   string 2
    modulehashes []modulehash 3

    hasmain uint8 // 1byte 1 if module contains the main function, 0 otherwise

    gcdatamask, gcbssmask bitvector 1+4byte *2 = 3

    typemap map[typeOff]*_type 1 // offset to *_rtype in previous module

    bad bool 1byte // module failed to load and should be ignored

    next *moduledata 1
  }
  @formatter:on
  */
  private long[] setModuleData(Program p, Address a, FlatProgramAPI flatapi, int pointerSize, MessageLog log)
      throws Exception {
    p.getListing().clearCodeUnits(a, a.add(pointerSize * 64 + 2), false);
    // pcHeader
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }

    a = a.add(pointerSize);
    // funcnametab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // cutab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // filetab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // pctab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // pclntable
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // ftab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // findfunctab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    } // when 64-bit
    a = a.add(pointerSize);
    // minpc, maxpc
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // text, etext
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // noptrdata, enoptrdata
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // data, edata
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // bss, ebss
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // noptrbss, enoptrbss
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // end, gcdata, gcbss
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // types, etypes
    Data data;
    Address type = flatapi.toAddr(0);
    try {
      flatapi.clearListing(a);
      data = flatapi.createData(a, new UnsignedLongDataType());
      type = (Address) data.getValue();
    } catch (Exception e) {
      log.appendException(e);
    }

    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new UnsignedLongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // textsectmap
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // typelinks
    Address typelink = flatapi.toAddr(0);
    try {
      flatapi.clearListing(a);
      data = flatapi.createData(a, new PointerDataType());
      typelink = (Address) data.getValue();
    } catch (Exception e) {
      log.appendException(e);
    }

    a = a.add(pointerSize);
    long typelinkLength = 0;
    try {
      flatapi.clearListing(a);
      data = flatapi.createData(a, new LongDataType());
      typelinkLength = (long) ((Scalar) data.getValue()).getValue();
    } catch (Exception e) {
      log.appendException(e);
    }

    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // itablinks
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // ptab
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // pluginpath
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // pkghashes
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // modulename
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // modulehashes
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new LongDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // hasmain
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new ByteDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(1);
    // gcdatamask, gcbssmask
    /*
    @formatter:off
    type bitvector struct {
      n        int32 // # of bits
      bytedata *uint8
    }
    @formatter:on
    */
    try {
      flatapi.clearListing(a);
      flatapi.clearListing(a);
      flatapi.createData(a, new ByteDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(4);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new IntegerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(4);
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // typemap
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new PointerDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(pointerSize);
    // bad
    try {
      flatapi.clearListing(a);
      flatapi.createData(a, new BooleanDataType());
    } catch (Exception e) {
      log.appendException(e);
    }
    a = a.add(1);
    // next
    flatapi.clearListing(a);
    data = flatapi.createData(a, new PointerDataType());
    a = (Address) data.getValue();
    return new long[] { type.getOffset(), typelink.getOffset(), typelinkLength, a.getOffset() };
  }

}
