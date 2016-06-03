//
//  Instrumenter.cpp
//  TaintAll
//
//  Created by Onur on 15/12/15.
//  Copyright © 2015 taintall. All rights reserved.
//

#include "Instrumenter.hpp"
#include <iostream>
#include <sstream>
#include <sys/syscall.h>
#include <boost/algorithm/string.hpp>


Tainter Instrumenter::tainter;
std::list<TAddr> Instrumenter::addrsToBeTainted;
std::list<TReg> Instrumenter::regsToBeTainted;
std::list<TAddr> Instrumenter::addrsToBeUntainted;
std::list<TReg> Instrumenter::regsToBeUntainted;
std::list<TPtr> Instrumenter::pointersToBeTainted;
std::list<TPtr> Instrumenter::pointersToBeUntainted;


IMGInfo Instrumenter::imgInfo;
readSysCall Instrumenter::lastReadSysCall;
bool Instrumenter::isEngineRunning;
UserCommands Instrumenter::usrCmd;
bool Instrumenter::isSERunning;
bool Instrumenter::isRegsCleared;
std::ofstream Instrumenter::resultFile;


KNOB<UINT64> KnobSIB(KNOB_MODE_WRITEONCE, "pintool", "sib", "0x100000000", "Static Image Base");
KNOB<UINT64> KnobTaintStart(KNOB_MODE_WRITEONCE, "pintool", "bt", "0x0", "Start Tainting");
KNOB<UINT64> KnobTaintStop(KNOB_MODE_WRITEONCE, "pintool", "et", "0x0", "Stop Tainting");
KNOB<string> KnobTaintPointer(KNOB_MODE_WRITEONCE, "pintool", "tp", "none", "Taint Pointer insaddr1,reg1,size1,insaddr2,reg2,size2");
KNOB<string> KnobTaintReg(KNOB_MODE_WRITEONCE, "pintool", "tr", "none", "Taint Register insaddr1,reg1,regpart1,insaddr2,reg2,regpart2");
KNOB<string> KnobTaintAddr(KNOB_MODE_WRITEONCE, "pintool", "ta", "none", "Taint Memory Address insaddr1,memaddr1,size1,insaddr2,memaddr2,size2");


bool Instrumenter::init(int argc, char** argv) {
    
    if (PIN_Init(argc, argv))
        return false;
    
    isEngineRunning = false;
    isSERunning = false;
    isRegsCleared = false;
    resultFile.open("results.ta");
    
    parseCmdLine();
    
    PIN_InitSymbols();
    PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(imgInstFunc, 0);
    INS_AddInstrumentFunction(insInstFunc, 0);
    PIN_AddSyscallEntryFunction(sysCallInstFunc, 0);
    PIN_AddFiniFunction(programFinFunc, 0);
    return true;
}

void Instrumenter::parseCmdLine() {
    vector<string>tpointers;
    vector<string>tregs;
    vector<string>taddrs;
    
    /*
    cout << hex << KnobSIB.Value() << endl;
    cout << hex << KnobTaintStart.Value() << endl;
    cout << hex << KnobTaintStop.Value() << endl;
    cout << KnobTaintPointer.Value() << endl;
    cout << KnobTaintReg.Value() << endl;
    cout << KnobTaintAddr.Value() << endl;
    */
    
    setStaticImageBase(KnobSIB.Value());
    startAt(KnobTaintStart.Value());
    stopAt(KnobTaintStop.Value());

    /* taint pointers */
    if(strncmp(KnobTaintPointer.Value().c_str(), "none", 4)) {
        boost::split(tpointers, KnobTaintPointer.Value(), boost::is_any_of(","));
        for (int i = 0; i < tpointers.size(); i += 3) {
            taintAtAddr(strtoul(tpointers[i].c_str(), NULL, 16),
                        static_cast<RegId>(atoi(tpointers[i+1].c_str())),
                        strtoul(tpointers[i+2].c_str(), NULL, 16));
        }
    }
    
    /* taint registers */
    if(strncmp(KnobTaintReg.Value().c_str(), "none", 4)) {
        boost::split(tregs, KnobTaintReg.Value(), boost::is_any_of(","));
        for (int i = 0; i < tregs.size(); i += 3) {
            taintAtAddr(strtoul(tregs[i].c_str(), NULL, 16),
                        static_cast<RegId>(atoi(tregs[i+1].c_str())),
                        Registers::getRegPartByOrdinal(atoi(tregs[i+2].c_str())));
        }
    }
    
    /* taint memories */
    if(strncmp(KnobTaintAddr.Value().c_str(), "none", 4)) {
        boost::split(taddrs, KnobTaintAddr.Value(), boost::is_any_of(","));
        for (int i = 0; i < taddrs.size(); i += 3) {
            taintAtAddr(strtoul(taddrs[i].c_str(), NULL, 16),
                        strtoul(taddrs[i+1].c_str(), NULL, 16),
                        strtoul(taddrs[i+2].c_str(), NULL, 16));
        }
    }
}


void Instrumenter::insInstFunc(INS ins, void *v) {
    InsData *insData;
    TA_UINT insAddr;
    
    
    if (!INS_Valid(ins))
        return;
    
    insAddr = INS_Address(ins);
    
    /* clear caller save registers */
    if (insAddr > OSX_SHARED_ADDR_SPACE && !isRegsCleared) {
        isRegsCleared = true;
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       (AFUNPTR)InstrumentHelper::clearRegs,
                       IARG_CONST_CONTEXT,
                       IARG_PTR, &tainter,
                       IARG_CALL_ORDER, CALL_ORDER_FIRST,
                       IARG_END);
        
        return;
    }

    
    if (!isEngineRunning && insAddr-imgInfo.pieIter == usrCmd.startTaint) {
        isEngineRunning = true;
    }
    
    if (isEngineRunning && insAddr-imgInfo.pieIter == usrCmd.stopTaint) {
        isEngineRunning = false;
    }
    
    if (!isEngineRunning)
        return;
    
    //TODO: check again
    if (INS_IsSyscall(ins)) {
        tainter.untaint(R_RAX, R_TA_QWORD);
        return;
    }
    
    isRegsCleared = false;

    insData = new InsData();
    insData->addr = insAddr;
    insData->mnemonic = INS_Disassemble(ins);
    insData->pieIter = imgInfo.pieIter;
    insData->opcode = INS_Opcode(ins);
    insData->size = INS_Size(ins);
    insData->rFile = &resultFile;
    

    /* Decide to be instrumented or not */
    INS_InsertCall(ins,
                   IPOINT_BEFORE,
                   (AFUNPTR)checkToBeInst,
                   IARG_CONST_CONTEXT,
                   IARG_INST_PTR,
                   IARG_CALL_ORDER, CALL_ORDER_FIRST,
                   IARG_END);


    /* Taint and follow instructions */
    if (INS_OperandCount(ins) > 1) {
        if (INS_MemoryOperandCount(ins) > 0 ) {
            if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)) {
                INS_InsertCall(ins,
                               IPOINT_BEFORE,
                               (AFUNPTR)InstrumentHelper::taintMemToReg,
                               IARG_CONST_CONTEXT,
                               IARG_PTR, insData,
                               IARG_PTR, &tainter,
                               IARG_MEMORYOP_EA, 0,
                               IARG_UINT32, REG(INS_OperandReg(ins, 0)),
                               IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                               IARG_END);
            } else if (INS_MemoryOperandIsWritten(ins, 0)) {
                if (INS_OperandCount(ins) == 2) {
                    if (INS_OperandIsImmediate(ins, 1)) {
                        INS_InsertCall(ins,
                                       IPOINT_BEFORE,
                                       (AFUNPTR)InstrumentHelper::taintImmToMem,
                                       IARG_CONST_CONTEXT,
                                       IARG_PTR, insData,
                                       IARG_PTR, &tainter,
                                       IARG_MEMORYOP_EA, 0,
                                       IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                                       IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                       IARG_END);
                    } else if (INS_OperandIsReg(ins, 1)) {
                        INS_InsertCall(ins,
                                       IPOINT_BEFORE,
                                       (AFUNPTR)InstrumentHelper::taintRegToMem,
                                       IARG_CONST_CONTEXT,
                                       IARG_PTR, insData,
                                       IARG_PTR, &tainter,
                                       IARG_MEMORYOP_EA, 0,
                                       IARG_UINT32, REG(INS_OperandReg(ins, 1)),
                                       IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                       IARG_END);
                    }
                } else if (INS_OperandCount(ins) == 4) {
                    if (INS_OperandIsImmediate(ins, 0)) {
                        INS_InsertCall(ins,
                                       IPOINT_BEFORE,
                                       (AFUNPTR)InstrumentHelper::taintImmToMem,
                                       IARG_CONST_CONTEXT,
                                       IARG_PTR, insData,
                                       IARG_PTR, &tainter,
                                       IARG_MEMORYOP_EA, 0,
                                       IARG_UINT32, INS_MemoryOperandSize(ins, 0),
                                       IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                       IARG_END);
                    } else if (INS_OperandIsReg(ins, 0)) {
                        INS_InsertCall(ins,
                                      IPOINT_BEFORE,
                                      (AFUNPTR)InstrumentHelper::taintRegToMem,
                                      IARG_CONST_CONTEXT,
                                      IARG_PTR, insData,
                                      IARG_PTR, &tainter,
                                      IARG_MEMORYOP_EA, 0,
                                      IARG_UINT32, REG(INS_OperandReg(ins, 0)),
                                      IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                      IARG_END);
                    }
                }
            }
        } else if (INS_OperandIsReg(ins, 0)) {
                if (INS_OperandIsImmediate(ins, 1) && INS_OperandWrittenOnly(ins,0)) {
                    INS_InsertCall(ins,
                                   IPOINT_BEFORE,
                                   (AFUNPTR)InstrumentHelper::taintImmToReg,
                                   IARG_CONST_CONTEXT,
                                   IARG_PTR, insData,
                                   IARG_PTR, &tainter,
                                   IARG_UINT32, REG(INS_OperandReg(ins, 0)),
                                   IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                   IARG_END);
                } else if (INS_OperandIsReg(ins, 1) && INS_OperandWrittenOnly(ins,0)) {
                    INS_InsertCall(ins,
                                   IPOINT_BEFORE,
                                   (AFUNPTR)InstrumentHelper::taintRegToReg,
                                   IARG_CONST_CONTEXT,
                                   IARG_PTR, insData,
                                   IARG_PTR, &tainter,
                                   IARG_UINT32, REG(INS_OperandReg(ins, 0)),
                                   IARG_UINT32, REG(INS_OperandReg(ins, 1)),
                                   IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
                                   IARG_END);
                }
        }
    } /* end of tainting */
    
    
    TInst* tinst = NULL; // it will be used for concolic execution.
    bool *isAnyTainted;
    isAnyTainted = (bool*) malloc(sizeof(bool));
   

    if (INS_IsLea(ins)) {
        
        //catch lea
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       (AFUNPTR)InstrumentHelper::analyseLea,
                       IARG_CONST_CONTEXT,
                       IARG_PTR, insData,
                       IARG_PTR, &tainter,
                       IARG_UINT32, INS_OperandMemoryBaseReg(ins,1),
                       IARG_UINT32, INS_OperandMemoryIndexReg(ins,1),
                       IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
                       IARG_UINT32, INS_OperandMemoryScale(ins,1),
                       IARG_PTR, tinst,
                       IARG_PTR, isAnyTainted,
                       IARG_CALL_ORDER, CALL_ORDER_FIRST+2,
                       IARG_END);
        
    } else {
        //look for memory operands
        if (INS_IsStandardMemop(ins) || INS_HasMemoryVector(ins)) {
            for (int i = 0; i < INS_MemoryOperandCount(ins); i++) {                
                INS_InsertCall(ins,
                               IPOINT_BEFORE,
                               (AFUNPTR)InstrumentHelper::analyseMem,
                               IARG_CONST_CONTEXT,
                               IARG_PTR, insData,
                               IARG_PTR, &tainter,
                               IARG_MEMORYOP_EA, i,
                               IARG_UINT32, INS_MemoryOperandSize(ins, i),
                               IARG_PTR, tinst,
                               IARG_PTR, isAnyTainted,
                               IARG_CALL_ORDER, CALL_ORDER_FIRST+2,
                               IARG_END);
            }
        }
        
        
        //look for register operands
        for (int i = 0; i < INS_OperandCount(ins); i++) {
            if(INS_OperandIsReg(ins, i)) {
                INS_InsertCall(ins,
                               IPOINT_BEFORE,
                               (AFUNPTR)InstrumentHelper::analyseReg,
                               IARG_CONST_CONTEXT,
                               IARG_PTR, insData,
                               IARG_PTR, &tainter,
                               IARG_UINT32, REG(INS_OperandReg(ins, i)),
                               IARG_PTR, tinst,
                               IARG_PTR, isAnyTainted,
                               IARG_CALL_ORDER, CALL_ORDER_FIRST+2,
                               IARG_END);
            }
        }
        
        
        //process tinst
        INS_InsertCall(ins,
                       IPOINT_BEFORE,
                       (AFUNPTR)InstrumentHelper::processTInst,
                       IARG_CONST_CONTEXT,
                       IARG_PTR, insData,
                       IARG_PTR, &tainter,
                       IARG_PTR, tinst,
                       IARG_PTR, isAnyTainted,
                       IARG_CALL_ORDER, CALL_ORDER_FIRST+3,
                       IARG_END);
    }
}

void Instrumenter::imgInstFunc(IMG img, void *v) {
    
    if (IMG_LowAddress(img) > OSX_SHARED_ADDR_SPACE)
        return;
    
    /* calculate pie iterator */
    imgInfo.imageBase = IMG_LowAddress(img);
    imgInfo.pieIter = imgInfo.imageBase - imgInfo.staticImageBase;
    
    std::cout << "Dynamic IMG Base: 0x" << std::hex << imgInfo.imageBase << std::endl;
    std::cout << "Static Base: 0x" << std::hex << imgInfo.staticImageBase << std::endl;
    std::cout << "PIE Iterator: 0x" << std::hex << imgInfo.pieIter << std::endl;
}


void Instrumenter::checkToBeInst(const CONTEXT* ctxt, TA_UINT instAddr) {

    TA_UINT regVal = 0;

    //pointers
    for (list<TPtr>::iterator i = pointersToBeTainted.begin(); i != pointersToBeTainted.end(); i++) {
        if (i->instAddr + imgInfo.pieIter == instAddr) {
            regVal = 0;
            PIN_GetContextRegval(ctxt, Registers::convertPINReg(i->reg), (UINT8*)&regVal);
            tainter.taint(regVal, i->msize);
        }
    }
    
    for (list<TPtr>::iterator i = pointersToBeUntainted.begin(); i != pointersToBeUntainted.end(); i++)
        if (i->instAddr + imgInfo.pieIter == instAddr) {
            regVal = 0;
            PIN_GetContextRegval(ctxt, Registers::convertPINReg(i->reg), (UINT8*)&regVal);
            tainter.untaint(regVal, i->msize);
        }
    
    //addresses
    for (list<TAddr>::iterator i = addrsToBeTainted.begin(); i != addrsToBeTainted.end(); i++)
        if (i->instAddr + imgInfo.pieIter == instAddr) {
            tainter.taint(i->memAddr, i->msize);
        }
    
    for (list<TAddr>::iterator i = addrsToBeUntainted.begin(); i != addrsToBeUntainted.end(); i++)
        if (i->instAddr + imgInfo.pieIter == instAddr)
            tainter.untaint(i->memAddr, i->msize);
    
    //registers
    for (list<TReg>::iterator i = regsToBeTainted.begin(); i != regsToBeTainted.end(); i++)
        if (i->instAddr + imgInfo.pieIter == instAddr) {
            tainter.taint(i->reg, i->rp);
        }
    
    for (list<TReg>::iterator i = regsToBeUntainted.begin(); i != regsToBeUntainted.end(); i++)
        if (i->instAddr + imgInfo.pieIter == instAddr) {
            tainter.untaint(i->reg, i->rp);
        }
}

void Instrumenter::programFinFunc(int code, void *v) {
    std::cout << "Program finished." << std::endl;
    
    resultFile.close();
}

void Instrumenter::setStaticImageBase(TA_UINT imgbase) {
    imgInfo.staticImageBase = imgbase;
}

void Instrumenter::taintAtAddr(TA_UINT instAddr, TA_UINT memAddr, TA_UINT msize) {
    TAddr taddr;
    taddr.instAddr = instAddr;
    taddr.memAddr = memAddr;
    taddr.msize = msize;
    addrsToBeTainted.push_back(taddr);
}

void Instrumenter::taintAtAddr(TA_UINT instAddr, RegId reg, RegPart rp) {
    TReg treg;
    treg.instAddr = instAddr;
    treg.reg = reg;
    treg.rp = rp;
    regsToBeTainted.push_back(treg);
}

void Instrumenter::unTaintAtAddr(TA_UINT instAddr, TA_UINT memAddr, TA_UINT msize) {
    TAddr taddr;
    taddr.instAddr = instAddr;
    taddr.memAddr = memAddr;
    taddr.msize = msize;
    addrsToBeUntainted.push_back(taddr);
}

void Instrumenter::unTaintAtAddr(TA_UINT instAddr, RegId reg, RegPart rp) {
    TReg treg;
    treg.instAddr = instAddr;
    treg.reg = reg;
    treg.rp = rp;
    regsToBeUntainted.push_back(treg);
}

void Instrumenter::taintAtAddr(TA_UINT instAddr, RegId reg, TA_UINT msize) {
    TPtr tptr;
    tptr.instAddr = instAddr;
    tptr.reg = reg;
    tptr.msize = msize;
    pointersToBeTainted.push_back(tptr);
}

void Instrumenter::unTaintAtAddr(TA_UINT instAddr, RegId reg, TA_UINT msize) {
    TPtr tptr;
    tptr.instAddr = instAddr;
    tptr.reg = reg;
    tptr.msize = msize;
    pointersToBeUntainted.push_back(tptr);
}

void Instrumenter::sysCallInstFunc(THREADID thread_id, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v) {
    if (isEngineRunning)
        cout << "Syscall Number: 0x" << std::hex << PIN_GetSyscallNumber(ctxt, std) << std::endl;
    /*
    if (PIN_GetSyscallNumber(ctxt, std) == (0x2000000 + (TA_UINT)SYS_read)) {
        ;
    }
     */
}

std::string Instrumenter::getRelativeAddr(TA_UINT virtualAddr, TA_UINT baseAddr) {
    long long int rAddr;
    std::stringstream result;
    
    rAddr = virtualAddr - baseAddr;
    
    if (rAddr < 0)
        result << "-0x" << std::hex << -rAddr;
    else
        result << "0x" << std::hex << rAddr;
    
    return result.str();
}


void Instrumenter::startAt(TA_UINT addr) {
    usrCmd.startTaint = addr;
}

void Instrumenter::stopAt(TA_UINT addr) {
    usrCmd.stopTaint = addr;
}

void Instrumenter::runProgram() {
    PIN_StartProgram();
}

void Instrumenter::clean() {
    ;
}

