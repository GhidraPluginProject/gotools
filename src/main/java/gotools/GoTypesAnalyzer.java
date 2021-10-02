package gotools;

import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GoTypesAnalyzer extends AnalyzerBase {

  public GoTypesAnalyzer() {
    super("Go Types Analyzer", "Analyzes Types like string and slices", AnalyzerType.FUNCTION_ANALYZER);
  }

  @Override
  public boolean added(Program program, AddressSetView addressSetView, TaskMonitor taskMonitor, MessageLog messageLog)
      throws CancelledException {
    createBaseTypes(program);
    createRTypes(program);
    return false;
  }

  private void createBaseTypes(Program p) {
    CategoryPath goPath = new CategoryPath("/go");
    StructureDataType s = new StructureDataType(goPath, "string", 0);
    s.add(new PointerDataType(new CharDataType()), "str", null);
    s.add(new QWordDataType(), "len", null);

    p.getDataTypeManager().addDataType(s, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType sl = new StructureDataType(goPath, "slice", 0);
    sl.add(new PointerDataType(), "data", null);
    sl.add(new QWordDataType(), "len", null);
    sl.add(new QWordDataType(), "cap", null);

    p.getDataTypeManager().addDataType(sl, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType si = new StructureDataType(goPath, "interface", 0);
    si.add(new PointerDataType(), "itab", null);
    si.add(new PointerDataType(), "data", null);

    p.getDataTypeManager().addDataType(si, DataTypeConflictHandler.KEEP_HANDLER);
  }

  private void createRTypes(Program p) {
    CategoryPath goPath = new CategoryPath("/go");
    DataTypeManager dtm = p.getDataTypeManager();
    StructureDataType arr = new StructureDataType("GoRArray", 0);
    arr.add(new PointerDataType(), 8, "elem", "array element type");
    arr.add(new PointerDataType(), 8, "slice", null);
    arr.add(new QWordDataType(), "len", null);

    dtm.addDataType(arr, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType chan = new StructureDataType("GoRChan", 0);
    chan.add(new PointerDataType(), "elem", "channel element type");
    chan.add(new QWordDataType(), "dir", "channel direction");

    dtm.addDataType(chan, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType func = new StructureDataType("GoRFunc", 0);
    func.add(new UnsignedShortDataType(), "in", "function argment number");
    func.add(new QWordDataType(), "out", "function return number");

    dtm.addDataType(func, DataTypeConflictHandler.KEEP_HANDLER);
    // internal type, there is no rtype before this type
    StructureDataType imethod = new StructureDataType("GoRInterfaceMethod", 0);
    imethod.add(new QWordDataType(), "nameOff", "name of method");
    imethod.add(new QWordDataType(), "typeOff", ".(*FuncType) underneath");

    dtm.addDataType(imethod, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType iface = new StructureDataType("GoRInterface", 0);
    iface.add(new QWordDataType(), "pkgPath", "import path");
    iface.add(dtm.getDataType(goPath, "slice"), "methods", "interface data");

    dtm.addDataType(iface, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType map = new StructureDataType("GoRMap", 0);
    map.add(new PointerDataType(), "key", "map key type");
    map.add(new PointerDataType(), "elem", "map element type");
    map.add(new PointerDataType(), "buckets", "hash function");
    map.add(new WordDataType(), "keysize", "size of key slot");
    map.add(new WordDataType(), "valuesize", "size of value slot");
    map.add(new DWordDataType(), "bucketsize", "size of bucket");
    map.add(new QWordDataType(), "flags", "flags");

    dtm.addDataType(map, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType ptr = new StructureDataType("GoRPtr", 0);
    ptr.add(new PointerDataType(), "elem", "pointer type");

    dtm.addDataType(ptr, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType slice = new StructureDataType("GoRSlice", 0);
    slice.add(new PointerDataType(), "data", "slice data");
    slice.add(new QWordDataType(), "elem", "slice element type");

    dtm.addDataType(slice, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType structfield = new StructureDataType("GoRStructField", 0);
    structfield.add(new PointerDataType(), "name", "name of field");
    structfield.add(new PointerDataType(), "typ", "type of field");
    structfield.add(new QWordDataType(), "offset", "offset of field");

    dtm.addDataType(structfield, DataTypeConflictHandler.KEEP_HANDLER);

    StructureDataType struct = new StructureDataType("GoRStruct", 0);
    struct.add(new PointerDataType(), "name", "name of struct");
    struct.add(dtm.getDataType(goPath, "slice"), "fields", "sorted by offset");

    dtm.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER);

  }
}
