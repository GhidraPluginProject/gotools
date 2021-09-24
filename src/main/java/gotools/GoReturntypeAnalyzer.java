/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gotools;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.StackReference;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Vector;

import ghidra.program.model.listing.CodeUnit;

/**
 * TODO: Provide class-level documentation that describes what this analyzer
 * does.
 */
public class GoReturntypeAnalyzer extends AnalyzerBase {
  private final String[] TYPE_KINDS = new String[] { "Invalid Kind", "Bool", "Int", "Int8", "Int16", "Int32", "Int64",
      "Uint", "Uint8", "Uint16", "Uint32", "Uint64", "Uintptr", "Float32", "Float64", "Complex64", "Complex128",
      "Array", "Chan", "Func", "Interface", "Map", "Ptr", "Slice", "String", "Struct", "UnsafePointer" };

  public GoReturntypeAnalyzer() {
    super("Go Return Type Analyzer", "Tries to recover the return type of go binaries.",
        AnalyzerType.FUNCTION_ANALYZER);
    setPriority(AnalysisPriority.LOW_PRIORITY);
  }

  @Override
  public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
    this.detectReturnTypes(p, monitor, log);
    return true;
  }

  private void detectReturnTypes(Program p, TaskMonitor m, MessageLog log) {
    try {
      detectModuleData(p, m, log);
    } catch (Exception e) {
      log.appendException(e);
    }

    for (Function f : p.getFunctionManager().getFunctionsNoStubs(true)) {
      detectReturnTypes116(p, m, log, f);
    }
  }

  private void detectReturnTypes116(Program p, TaskMonitor m, MessageLog log, Function f) {
    int maxOffset = 0;
    int maxWrite = 0;
    int minWrite = Integer.MAX_VALUE;
    m.setMessage(String.format("return type analysis of %s", f.getName()));
    if (!f.getName().contains("main.A")) {
      // return;
    }
    try {
      f.setCallingConvention("unknown");
    } catch (InvalidInputException e) {
      log.appendException(e);
    }
    ReferenceManager refMgr = p.getReferenceManager();
    for (Address fromAddr : refMgr.getReferenceSourceIterator(f.getBody(), true)) {
      for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
        if (!ref.isStackReference()) {
          continue;
        }
        StackReference stackRef = (StackReference) ref;
        if (stackRef.getStackOffset() < 0) {
          continue;
        }
        if (stackRef.getStackOffset() > maxOffset) {
          maxOffset = stackRef.getStackOffset();
        }
        if (ref.getReferenceType() != RefType.WRITE) {
          continue; // no indicator of "return" type
        }
        if (stackRef.getStackOffset() > maxWrite) {
          maxWrite = stackRef.getStackOffset();
        }
        if (stackRef.getStackOffset() < minWrite) {
          minWrite = stackRef.getStackOffset();
        }
      }
    }
    // TODO only works for 64 bit binaries
    int pointerSize = 8;
    long totalArgReturnVals = maxOffset / pointerSize;
    int numberOfRet = 0;
    if (minWrite <= maxWrite) {
      numberOfRet = (maxWrite - minWrite) / pointerSize + 1;
    }
    if (totalArgReturnVals > 10) {
      log.appendMsg(String.format("Skipped function %s because it has %d arguments", f.getName(), totalArgReturnVals));
      return;
    }
    long numberOfArgs = totalArgReturnVals - numberOfRet;
    // 1. Set arguments
    int paramenterLen = 0;
    for (Parameter param : f.getParameters()) {
      paramenterLen += param.getLength();
    }
    if (paramenterLen != numberOfArgs) {
      // Set the parameters
      Parameter[] params = f.getParameters();
      List<Variable> newParams = new Vector<>();
      for (int i = 0; i < numberOfArgs; i++) {
        if (params != null && params.length > i) {
          newParams.add(params[i]);
        } else {
          VariableStorage v = f.getCallingConvention().getArgLocation(i, params, new Undefined8DataType(), p);
          try {
            Variable var = new ParameterImpl(null, new Undefined8DataType(), v, p, SourceType.ANALYSIS);
            newParams.add(var); // TODO why so complicated?!
          } catch (InvalidInputException e) {
            log.appendException(e);
            return;
          }
        }
      }
      try {
        f.replaceParameters(newParams, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, false,
            SourceType.ANALYSIS);
      } catch (DuplicateNameException | InvalidInputException e) {
        log.appendException(e);
        return;
      }
    }
    // set return type
    f.setCustomVariableStorage(true);
    if (f.getReturnType().getLength() != numberOfRet * pointerSize
        || (numberOfRet != 0 && f.getReturn().getStackOffset() != minWrite)) {
      try {
        switch (numberOfRet) {
          case 0:
            f.setReturnType(DataType.VOID, SourceType.ANALYSIS);
            break;
          case 1:
            Undefined8DataType t = new Undefined8DataType();
            // The type is set to imported because otherwise we cannot overwrite it
            f.setReturn(t, new VariableStorage(p, minWrite, t.getLength()), SourceType.IMPORTED);
            break;
          default:
            StructureDataType s = new StructureDataType(String.format("ret_%d", f.getSymbol().getID()), 0);
            for (int i = 0; i < numberOfRet; i++) {
              s.add(new Undefined8DataType());
            }
            // The type is set to imported because otherwise we cannot overwrite it
            f.setReturn(s, new VariableStorage(p, minWrite, s.getLength()), SourceType.IMPORTED);
            break;
        }
      } catch (InvalidInputException e) {
        log.appendException(e);
      }
    }
    System.out.printf("Function %s has %d arguments and %d return values. Max offset: %d\n", f.getName(), numberOfArgs,
        numberOfRet, maxOffset);
  }

  private void detectModuleData(Program p, TaskMonitor m, MessageLog log) {
    // TODO only works for 64 bit binaries
    int pointerSize = 8;
    FlatProgramAPI flatapi = new FlatProgramAPI(p, m);
    try {
      Address gopcln = getGopclntab(p).getStart();
      long l = gopcln.getOffset();
      byte[] b = new byte[] { (byte) l, (byte) (l >> 8), (byte) (l >> 16), (byte) (l >> 24), (byte) (l >> 32),
          (byte) (l >> 40), (byte) (l >> 48), (byte) (l >> 56) };
      Address moduleData = flatapi.find(gopcln, b);
      int cnt = 0;
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
              idx = idx & ((1 << 5) - 1);
              if (idx > 27) {
                idx = 0;
              }
              String kind = TYPE_KINDS[idx];
              typelinkAddr = typelinkAddr.add(4);
              if (kind == "Func") { // TODO other types
                short[] funcArgmentAndReturn = setFuncType(typeAddress, flatapi, pointerSize);
                p.getListing().setComment(typeAddress, CodeUnit.EOL_COMMENT,
                    "in:" + funcArgmentAndReturn[0] + " out:" + funcArgmentAndReturn[1]);
              }
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
    flatapi.createData(a, new IntegerDataType());
    a = a.add(4);
    // ptrToThis
    flatapi.clearListing(a);
    flatapi.createData(a, new IntegerDataType());
    a = a.add(4);
    return new long[] { kind, a.getOffset() };
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
      data = flatapi.createData(a, new PointerDataType());
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
