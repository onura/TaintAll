//
//  InstrumentHelper.hpp
//  TaintAll
//
//  Created by Onur on 06/01/16.
//  Copyright © 2016 taintall. All rights reserved.
//

#ifndef InstrumentHelper_hpp
#define InstrumentHelper_hpp

#include "Tainter.hpp"
#include "pin.H"
#include "Registers.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>


class InsData {
public:
    TA_UINT addr;
    TA_UINT pieIter;
    TA_UINT opcode;
    UINT32 size;
    std::string mnemonic;
    std::ofstream* rFile;
};

typedef void TInst;

class InstrumentHelper {    
public:    
    /* methods */
    static void taintMemToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TA_UINT memEA, REG reg);
    static void taintImmToMem(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TA_UINT memEA, short immSize);
    static void taintRegToMem(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TA_UINT memEA, REG reg);
    static void taintImmToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, REG reg);
    static void taintRegToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, REG dstReg, REG srcReg);
    
    static void printInfo(InsData *insData, Tainter *tainter);
    static void printFormatted(InsData *insData, Tainter *tainter);
    
    static void analyseLea(const CONTEXT *ctxt, InsData *insData, Tainter * tainter, REG baseReg, REG indexReg, long int displacement, UINT32 scale, TInst* tinst, bool* isAnyTainted);
    static void analyseMem(const CONTEXT *ctxt, InsData *insData, Tainter * tainter, TA_UINT memEA, short immSize, TInst* tinst, bool* isAnyTainted);
    static void analyseReg(const CONTEXT *ctxt, InsData *insData, Tainter * tainter, REG reg, TInst* tinst, bool* isAnyTainted);
    static void processTInst(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TInst* tinst, bool* isAnyTainted);
    
    static string getOpcodeBytes(TA_UINT addr, short size);
    static string getOpcodeStr(TA_UINT addr, short size);
    static void clearRegs(const CONTEXT *ctxt, Tainter *tainter);
    


};

#endif /* InstrumentHelper_hpp */


