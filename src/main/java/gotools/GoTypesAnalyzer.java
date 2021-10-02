package gotools;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DoubleComplexDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatComplexDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoTypesAnalyzer extends AnalyzerBase {
  private final String[] TYPE_KINDS = new String[] { "Invalid Kind", "Bool", "Int", "Int8", "Int16", "Int32", "Int64",
      "Uint", "Uint8", "Uint16", "Uint32", "Uint64", "Uintptr", "Float32", "Float64", "Complex64", "Complex128",
      "Array", "Chan", "Func", "Interface", "Map", "Ptr", "Slice", "String", "Struct", "UnsafePointer" };
  private final CategoryPath goPath = new CategoryPath("/go");
  private final CategoryPath rtypePath = new CategoryPath("/go/rtype");

  public GoTypesAnalyzer(String name, String description, AnalyzerType type) {
    super(name, description, type);
  }

  @Override
  public boolean added(Program program, AddressSetView addressSetView, TaskMonitor taskMonitor, MessageLog messageLog)
      throws CancelledException {
    // TODO: dont run these functions more than two times
    createBaseTypes(program);
    createRTypes(program);
    analyzeModuleData(program, taskMonitor, messageLog);
    return false;
  }

  private void createBaseTypes(Program p) {
    StructureDataType s = new StructureDataType(goPath, "String", 0);
    s.add(new PointerDataType(new CharDataType()), "str", null);
    s.add(new QWordDataType(), "len", null);

    p.getDataTypeManager().addDataType(s, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType sl = new StructureDataType(goPath, "Slice", 0);
    sl.add(new PointerDataType(), "data", null);
    sl.add(new QWordDataType(), "len", null);
    sl.add(new QWordDataType(), "cap", null);

    p.getDataTypeManager().addDataType(sl, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType si = new StructureDataType(goPath, "Interface", 0);
    si.add(new PointerDataType(), "itab", null);
    si.add(new PointerDataType(), "data", null);

    p.getDataTypeManager().addDataType(si, DataTypeConflictHandler.KEEP_HANDLER);
  }

  private void createRTypes(Program p) {

    DataTypeManager dtm = p.getDataTypeManager();
    StructureDataType rtype = new StructureDataType(rtypePath, "Rtype", 0);
    rtype.add(new QWordDataType(), "size", null);
    rtype.add(new QWordDataType(), "ptrdata", null);
    rtype.add(new QWordDataType(), "hash", null);
    rtype.add(new WordDataType(), "tflag", null);
    rtype.add(new WordDataType(), "align", null);
    rtype.add(new WordDataType(), "fieldAlign", null);
    rtype.add(new WordDataType(), "kind", null);
    rtype.add(new PointerDataType(), "equal", null);
    rtype.add(new PointerDataType(), "gcdata", null);
    rtype.add(new QWordDataType(), "str", null);
    rtype.add(new QWordDataType(), "ptrToThis", null);

    dtm.addDataType(rtype, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType bitvector = new StructureDataType(rtypePath, "Bitvector", 0);
    bitvector.add(new QWordDataType(), "n", null);
    bitvector.add(new PointerDataType(), "bytedata", null);

    StructureDataType moduledata = new StructureDataType(rtypePath, "Moduledata", 0);
    moduledata.add(new PointerDataType(), "pcHeader", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "funcnametab", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "cutab", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "filetab", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "pctab", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "pclntable", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "ftab", null);
    moduledata.add(new QWordDataType(), "findfunctab", null);
    moduledata.add(new QWordDataType(), "minpc", null);
    moduledata.add(new QWordDataType(), "maxpc", null);
    moduledata.add(new QWordDataType(), "text", null);
    moduledata.add(new QWordDataType(), "etext", null);
    moduledata.add(new QWordDataType(), "noptrdata", null);
    moduledata.add(new QWordDataType(), "enoptrdata", null);
    moduledata.add(new QWordDataType(), "data", null);
    moduledata.add(new QWordDataType(), "edata", null);
    moduledata.add(new QWordDataType(), "bss", null);
    moduledata.add(new QWordDataType(), "ebss", null);
    moduledata.add(new QWordDataType(), "noptrbss", null);
    moduledata.add(new QWordDataType(), "enoptrbss", null);
    moduledata.add(new QWordDataType(), "end", null);
    moduledata.add(new QWordDataType(), "gcdata", null);
    moduledata.add(new QWordDataType(), "gcbss", null);
    moduledata.add(new QWordDataType(), "types", null);
    moduledata.add(new QWordDataType(), "etypes", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "textsectmap", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "typelinks", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "itablinks", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "ptab", null);
    moduledata.add(dtm.getDataType(goPath, "String"), "pluginpath", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "pkghashes", null);
    moduledata.add(dtm.getDataType(goPath, "String"), "modulename", null);
    moduledata.add(dtm.getDataType(goPath, "Slice"), "modulehashes", null);
    moduledata.add(new ByteDataType(), "hasmain", null);
    moduledata.add(bitvector, "gcdatamask", null);
    moduledata.add(bitvector, "gcbssmask", null);
    moduledata.add(new PointerDataType(), "typemap", null);
    moduledata.add(new ByteDataType(), "bad", null);
    moduledata.add(new PointerDataType(), "next", null);

    dtm.addDataType(moduledata, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType arr = new StructureDataType(rtypePath, "Array", 0);
    arr.add(new PointerDataType(), 8, "elem", "array element type");
    arr.add(new PointerDataType(), 8, "slice", null);
    arr.add(new QWordDataType(), "len", null);

    dtm.addDataType(arr, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType chan = new StructureDataType(rtypePath, "Chan", 0);
    chan.add(new PointerDataType(), "elem", "channel element type");
    chan.add(new QWordDataType(), "dir", "channel direction");

    dtm.addDataType(chan, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType func = new StructureDataType(rtypePath, "Func", 0);
    func.add(new UnsignedShortDataType(), "in", "function argment number");
    func.add(new QWordDataType(), "out", "function return number");

    dtm.addDataType(func, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType imethod = new StructureDataType(rtypePath, "InterfaceMethod", 0);
    imethod.add(new QWordDataType(), "nameOff", "name of method");
    imethod.add(new QWordDataType(), "typeOff", ".(*FuncType) underneath");

    dtm.addDataType(imethod, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType iface = new StructureDataType(rtypePath, "Interface", 0);
    iface.add(new QWordDataType(), "pkgPath", "import path");
    iface.add(dtm.getDataType(goPath, "Slice"), "methods", "interface data");

    dtm.addDataType(iface, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType map = new StructureDataType(rtypePath, "Map", 0);
    map.add(new PointerDataType(), "key", "map key type");
    map.add(new PointerDataType(), "elem", "map element type");
    map.add(new PointerDataType(), "buckets", "hash function");
    map.add(new WordDataType(), "keysize", "size of key slot");
    map.add(new WordDataType(), "valuesize", "size of value slot");
    map.add(new DWordDataType(), "bucketsize", "size of bucket");
    map.add(new QWordDataType(), "flags", "flags");

    dtm.addDataType(map, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType ptr = new StructureDataType(rtypePath, "Ptr", 0);
    ptr.add(new PointerDataType(), "elem", "pointer type");

    dtm.addDataType(ptr, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType slice = new StructureDataType(rtypePath, "Slice", 0);
    slice.add(new PointerDataType(), "data", "slice data");
    slice.add(new QWordDataType(), "elem", "slice element type");

    dtm.addDataType(slice, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType structfield = new StructureDataType(rtypePath, "StructField", 0);
    structfield.add(new PointerDataType(), "name", "name of field");
    structfield.add(new PointerDataType(), "typ", "type of field");
    structfield.add(new QWordDataType(), "offset", "offset of field");

    dtm.addDataType(structfield, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType struct = new StructureDataType(rtypePath, "Struct", 0);
    struct.add(new PointerDataType(), "name", "name of struct");
    struct.add(dtm.getDataType(goPath, "Slice"), "fields", "sorted by offset");

    dtm.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER);

  }

  private void analyzeModuleData(Program p, TaskMonitor m, MessageLog log) {
    try {
      Address gopcln = getGopclntab(p).getStart();
      long l = gopcln.getOffset();
      byte[] b = new byte[] { (byte) l, (byte) (l >> 8), (byte) (l >> 16), (byte) (l >> 24), (byte) (l >> 32),
          (byte) (l >> 40), (byte) (l >> 48), (byte) (l >> 56) };
      Address moduleData = p.getMemory().findBytes(gopcln, b, null, true, m);
      while (moduleData.getOffset() != 0) {
        try {
          Map<String, Data> types = setModuleData(p, moduleData);
          moduleData = (Address) types.get("next").getValue();
          Address typeBase = (Address) types.get("types").getValue();
          Data typelink = types.get("typelinks");
          Address typelinkAddr = (Address) p.getAddressFactory().getDefaultAddressSpace()
              .getAddress((long) typelink.getComponent(0).getValue());
          long length = (long) ((Scalar) typelink.getComponent(1).getValue()).getValue();
          for (int i = 0; i < length; i++) {
            try {
              p.getListing().clearCodeUnits(typelinkAddr, typelinkAddr.add(new IntegerDataType().getLength()), true);
              Data data = p.getListing().createData(typelinkAddr, new IntegerDataType());
              long offset = ((Scalar) data.getValue()).getValue();
              Address typeAddress = p.getAddressFactory().getDefaultAddressSpace()
                  .getAddress(typeBase.getOffset() + offset);
              Map<String, Data> rtype = setRType(p, typeAddress);
              int idx = (int) rtype.get("kind").getValue();
              typeAddress = typeAddress.add(p.getDataTypeManager().getDataType(rtypePath, "RType").getLength());
              idx = idx & ((1 << 5) - 1); // mask kind
              if (idx > 27) {
                idx = 0;
              }
              String kind = TYPE_KINDS[idx];
              typelinkAddr = typelinkAddr.add(new IntegerDataType().getLength());
              p.getListing().setComment(typeAddress, CodeUnit.EOL_COMMENT, "kind: " + kind);
              switch (kind) {
                case "Bool":
                  p.getListing().createData(typeAddress, new BooleanDataType());
                  break;
                case "Int":
                  p.getListing().createData(typeAddress, new IntegerDataType());
                  break;
                case "Int8":
                  p.getListing().createData(typeAddress, new ByteDataType());
                  break;
                case "Int16":
                  p.getListing().createData(typeAddress, new ShortDataType());
                  break;
                case "Int32":
                  p.getListing().createData(typeAddress, new IntegerDataType());
                  break;
                case "Int64":
                  p.getListing().createData(typeAddress, new LongDataType());
                  break;
                case "Uint":
                  p.getListing().createData(typeAddress, new UnsignedIntegerDataType());
                  break;
                case "Uint8":
                  p.getListing().createData(typeAddress, new UnsignedCharDataType());
                  break;
                case "Uint16":
                  p.getListing().createData(typeAddress, new UnsignedShortDataType());
                  break;
                case "Uint32":
                  p.getListing().createData(typeAddress, new UnsignedIntegerDataType());
                  break;
                case "Uint64":
                  p.getListing().createData(typeAddress, new UnsignedLongDataType());
                  break;
                case "Uintptr": // TODO: only 64bit
                  p.getListing().createData(typeAddress, new UnsignedLongDataType());
                  break;
                case "Float32":
                  p.getListing().createData(typeAddress, new FloatDataType());
                  break;
                case "Float64":
                  p.getListing().createData(typeAddress, new DoubleDataType());
                  break;
                case "Complex64":
                  p.getListing().createData(typeAddress, new FloatComplexDataType());
                  break;
                case "Complex128":
                  p.getListing().createData(typeAddress, new DoubleComplexDataType());
                  break;
                case "Array":
                  setRArrayType(p, typeAddress);
                  break;
                case "Chan":
                  setRChanType(p, typeAddress);
                  break;
                case "Func":
                  Map<String, Data> funcArgmentAndReturn = setRFuncType(p, typeAddress);
                  p.getListing().setComment(typeAddress, CodeUnit.EOL_COMMENT, "kind: " + kind + "/in:"
                      + funcArgmentAndReturn.get("inCount") + " out:" + funcArgmentAndReturn.get("outCount"));
                  break;
                case "Interface":
                  setRInterfaceType(p, typeAddress);
                  break;
                case "Map":
                  setRMapType(p, typeAddress);
                  break;
                case "Ptr":
                  setRPtrType(p, typeAddress);
                  break;
                case "Slice":
                  setRSliceType(p, typeAddress);
                  break;
                case "String":
                  p.getListing().createData(typeAddress, p.getDataTypeManager().getDataType(goPath, "String"));
                  break;
                case "Struct":
                  setRStructType(p, typeAddress);
                  break;
                case "UnsafePointer":
                  p.getListing().createData(typeAddress, new PointerDataType());
                default:
                  break;
              }

            } catch (Exception e) {
              log.appendException(e);
            }
          }
        } catch (Exception e) {
          log.appendException(e);
          break;
        }

      }
    } catch (Exception e) {
      log.appendException(e);
    }
  }

  private Map<String, Data> setRArrayType(Program p, Address a) throws Exception {
    DataType arrayType = p.getDataTypeManager().getDataType(rtypePath, "Array");
    p.getListing().clearCodeUnits(a, a.add(arrayType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, arrayType);
    ret.put("elem", d.getComponent(0));
    ret.put("slice", d.getComponent(1));
    ret.put("len", d.getComponent(2));
    return ret;
  }

  private Map<String, Data> setRChanType(Program p, Address a) throws Exception {
    DataType chanType = p.getDataTypeManager().getDataType(rtypePath, "Chan");
    p.getListing().clearCodeUnits(a, a.add(chanType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, chanType);
    ret.put("elem", d.getComponent(0));
    ret.put("dir", d.getComponent(1));
    return ret;
  }

  private Map<String, Data> setRFuncType(Program p, Address a) throws Exception {
    DataType funcType = p.getDataTypeManager().getDataType(rtypePath, "Func");
    p.getListing().clearCodeUnits(a, a.add(funcType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, funcType);
    ret.put("inCount", d.getComponent(0));
    ret.put("outCount", d.getComponent(1));
    return ret;
  }

  private Map<String, Data> setRInterfaceType(Program p, Address a) throws Exception {
    DataType interfaceType = p.getDataTypeManager().getDataType(rtypePath, "Interface");
    p.getListing().clearCodeUnits(a, a.add(interfaceType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, interfaceType);
    ret.put("pkgPath", d.getComponent(0));
    ret.put("methods", d.getComponent(1));
    return ret;
  }

  private Map<String, Data> setRMapType(Program p, Address a) throws Exception {
    DataType mapType = p.getDataTypeManager().getDataType(rtypePath, "Map");
    p.getListing().clearCodeUnits(a, a.add(mapType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, mapType);
    ret.put("key", d.getComponent(0));
    ret.put("elem", d.getComponent(1));
    ret.put("bucket", d.getComponent(2));
    ret.put("hasher", d.getComponent(3));
    ret.put("keysize", d.getComponent(4));
    ret.put("valuesize", d.getComponent(5));
    ret.put("bucketsize", d.getComponent(6));
    ret.put("flags", d.getComponent(7));
    return ret;
  }

  private Map<String, Data> setRPtrType(Program p, Address a) throws Exception {
    DataType ptrType = p.getDataTypeManager().getDataType(rtypePath, "Ptr");
    p.getListing().clearCodeUnits(a, a.add(ptrType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, ptrType);
    ret.put("elem", d.getComponent(0));
    return ret;
  }

  private Map<String, Data> setRSliceType(Program p, Address a) throws Exception {
    DataType sliceType = p.getDataTypeManager().getDataType(rtypePath, "Slice");
    p.getListing().clearCodeUnits(a, a.add(sliceType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, sliceType);
    ret.put("elem", d.getComponent(0));
    return ret;
  }

  private Map<String, Data> setRStructType(Program p, Address a) throws Exception {
    DataType structType = p.getDataTypeManager().getDataType(rtypePath, "Struct");
    p.getListing().clearCodeUnits(a, a.add(structType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, structType);
    ret.put("pkgPath", d.getComponent(0));
    ret.put("fields", d.getComponent(1));
    return ret;
  }

  private Map<String, Data> setRType(Program p, Address a) throws Exception {
    DataType rType = p.getDataTypeManager().getDataType(rtypePath, "Rtype");
    p.getListing().clearCodeUnits(a, a.add(rType.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, rType);
    ret.put("size", d.getComponent(0));
    ret.put("ptrdata", d.getComponent(1));
    ret.put("hash", d.getComponent(2));
    ret.put("tflag", d.getComponent(3));
    ret.put("align", d.getComponent(4));
    ret.put("fieldAlign", d.getComponent(5));
    ret.put("kind", d.getComponent(6));
    ret.put("equal", d.getComponent(7));
    ret.put("gcdata", d.getComponent(8));
    ret.put("str", d.getComponent(9));
    ret.put("ptrToThis", d.getComponent(10));
    return ret;
  }

  private Map<String, Data> setModuleData(Program p, Address a) throws Exception {
    DataType moduleData = p.getDataTypeManager().getDataType(rtypePath, "Moduledata");
    p.getListing().clearCodeUnits(a, a.add(moduleData.getLength()), true);
    Map<String, Data> ret = new HashMap<>();
    Data d = p.getListing().createData(a, moduleData);
    ret.put("pcHeader", d.getComponent(0));
    ret.put("funcnametab", d.getComponent(1));
    ret.put("cutab", d.getComponent(2));
    ret.put("filetab", d.getComponent(3));
    ret.put("pctab", d.getComponent(4));
    ret.put("pclntable", d.getComponent(5));
    ret.put("ftab", d.getComponent(6));
    ret.put("findfunctab", d.getComponent(7));
    ret.put("minpc", d.getComponent(8));
    ret.put("maxpc", d.getComponent(9));
    ret.put("text", d.getComponent(10));
    ret.put("etext", d.getComponent(11));
    ret.put("noptrdata", d.getComponent(12));
    ret.put("enoptrdata", d.getComponent(13));
    ret.put("data", d.getComponent(14));
    ret.put("edata", d.getComponent(15));
    ret.put("bss", d.getComponent(16));
    ret.put("ebss", d.getComponent(17));
    ret.put("noptrbss", d.getComponent(18));
    ret.put("enoptrbss", d.getComponent(19));
    ret.put("end", d.getComponent(20));
    ret.put("gcdata", d.getComponent(21));
    ret.put("gcbss", d.getComponent(22));
    ret.put("types", d.getComponent(23));
    ret.put("etypes", d.getComponent(24));
    ret.put("textsectmap", d.getComponent(25));
    ret.put("typelinks", d.getComponent(26));
    ret.put("itablinks", d.getComponent(27));
    ret.put("ptab", d.getComponent(28));
    ret.put("pluginpath", d.getComponent(29));
    ret.put("pkghashes", d.getComponent(30));
    ret.put("modulename", d.getComponent(31));
    ret.put("modulehashes", d.getComponent(32));
    ret.put("hasmain", d.getComponent(33));
    ret.put("gcdatamask", d.getComponent(34));
    ret.put("gcbssmask", d.getComponent(35));
    ret.put("typemap", d.getComponent(36));
    ret.put("bad", d.getComponent(37));
    ret.put("next", d.getComponent(38));
    return ret;
  }
}
