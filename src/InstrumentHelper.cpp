//
//  InstrumentHelper.cpp
//  TaintAll
//
//  Created by Onur on 06/01/16.
//  Copyright © 2016 taintall. All rights reserved.
//

#include "InstrumentHelper.hpp"

#define TA_DEBUG 6


void InstrumentHelper::taintMemToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter,
                                     TA_UINT memEA, REG reg) {

    RegId tmpReg;
    RegPart tmpPart;
    
    tmpReg = Registers::parsePINReg(reg, &tmpPart);
    
    if (tmpReg == R_END) return;
    
    tainter->spreadTaintRM(tmpReg, tmpPart, memEA);
    
    if (TA_DEBUG == 1) {
        cout << "taintMemToReg: 0x" << hex << memEA << " - " << dec << Registers::getRegName(Registers::parsePINReg(reg, &tmpPart), R_TA_QWORD) << endl;
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 2) {
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 4) {
        if (tainter->isTainted(tmpReg, tmpPart)) {
            printInfo(insData, tainter);
        }
    }
}

void InstrumentHelper::taintImmToMem(const CONTEXT *ctxt, InsData *insData, Tainter *tainter,
                                     TA_UINT memEA, short immSize) {
    
    tainter->spreadTaintMI(memEA, immSize);
    
    if (TA_DEBUG == 1) {
        cout << "taintImmToMem: 0x" << hex << memEA << " - " << dec << immSize << endl;
        printInfo(insData, tainter);
        
    } else if (TA_DEBUG == 2) {
        printInfo(insData, tainter);
    }
}

void InstrumentHelper::taintRegToMem(const CONTEXT *ctxt, InsData *insData, Tainter *tainter,
                                     TA_UINT memEA, REG reg) {
    RegId tmpReg;
    RegPart tmpPart;

    tmpReg = Registers::parsePINReg(reg, &tmpPart);
    
    if (tmpReg != R_END) {
        tainter->spreadTaintMR(memEA, tmpReg, tmpPart);
    }
    
    if (TA_DEBUG == 1) {
        cout << "taintRegToMem:" << dec << Registers::getRegName(tmpReg, tmpPart) << "\tmem: 0x" << hex << memEA << endl;
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 2) {
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 4) {
        if (tainter->isTainted(memEA)) {
            printInfo(insData, tainter);
        }
    }
}

void InstrumentHelper::taintImmToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter,
                                     REG reg) {
    RegId tmpReg;
    RegPart tmpPart;
    
    tmpReg = Registers::parsePINReg(reg, &tmpPart);
    tainter->spreadTaintRI(tmpReg, tmpPart);
    
    if (TA_DEBUG == 1) {
        cout << "taintImmToReg: " << Registers::getRegName(Registers::parsePINReg(reg, &tmpPart), R_TA_QWORD) << endl;
        printInfo(insData, tainter);

    } else if (TA_DEBUG == 2) {
        printInfo(insData, tainter);
    }
}

void InstrumentHelper::taintRegToReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter,
                                    REG dstReg, REG srcReg) {
    RegId tmpReg, tmpReg2;
    RegPart tmpPart, tmpPart2;
    
    tmpReg = Registers::parsePINReg(dstReg, &tmpPart);
    tmpReg2 = Registers::parsePINReg(srcReg, &tmpPart2);
    
    /* 
     cout << Registers::getRegName(tmpReg, tmpPart) << "," << Registers::getRegName(tmpReg2, tmpPart2);
     */
    
    tainter->spreadTaintRR(tmpReg, tmpPart, tmpReg2, tmpPart2);
    
    if (TA_DEBUG == 1) {
        cout << "taintRegToReg" << endl;
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 2) {
        printInfo(insData, tainter);
    } else if (TA_DEBUG == 4) {
        if (tainter->isTainted(tmpReg, tmpPart)) {
            printInfo(insData, tainter);
        }
    }
}


void InstrumentHelper::printInfo(InsData *insData, Tainter *tainter) {
    bool tr[R_END][R_TA_OWORD];
    std::list<TA_UINT> ta;

    
    if (insData->addr - insData->pieIter > OSX_SHARED_ADDR_SPACE) {
        cout.setstate(std::ios_base::badbit);
    } else {
        cout.clear();
    }
    
    /* print instruction */
    cout << std::hex << insData->addr - insData->pieIter << "\t" << insData->mnemonic << std::endl;
    
    /* print tainted registers */
    cout << "Tainted Regs" << std::endl;
    tainter->getTaintedRegs(tr);
    Registers::printTaintedRegs(tr);
    
    /* print tainted addresses */
    cout << "Tainted Mems" << std::endl;
    ta = tainter->getTaintedMem();
    for (std::list<TA_UINT>::iterator iter = ta.begin(); iter != ta.end(); iter++) {
        cout << "0x" << hex << *iter << endl;
    }
    cout << "-----------" << endl;
    
}

void InstrumentHelper::printFormatted(InsData *insData, Tainter *tainter) {
    bool tr[R_END][R_TA_OWORD];
    std::list<TA_UINT> ta;

    
    *(insData->rFile) << "T,0x" << std::hex << insData->addr - insData->pieIter << ",";
    
    *(insData->rFile) << "tregs:";
    tainter->getTaintedRegs(tr);
    Registers::printTaintedRegs(tr, insData->rFile);
    *(insData->rFile) << ",";
    
    *(insData->rFile) << "tmems:";
    ta = tainter->getTaintedMem();
    for (std::list<TA_UINT>::iterator iter = ta.begin(); iter != ta.end(); iter++) {
        *(insData->rFile) << "0x" << hex << *iter << ":";
    }

    *(insData->rFile) << std::endl;
}

void InstrumentHelper::analyseLea(const CONTEXT *ctxt, InsData *insData, Tainter * tainter, REG baseReg, REG indexReg, long int displacement, UINT32 scale, TInst* tinst, bool* isAnyTainted) {
    TA_UINT base = 0;
    TA_UINT index = 0;
    TA_UINT memEA;
    
    if (baseReg != REG_INVALID())
        PIN_GetContextRegval(ctxt, baseReg, (UINT8*)&base);
    if (indexReg != REG_INVALID())
        PIN_GetContextRegval(ctxt, indexReg, (UINT8*)&index);
    
    memEA = displacement + base + index * scale;
    
    //cout << std::hex << insData->addr - insData->pieIter << "\t" << insData->mnemonic << "---" << hex << memEA << " - val:"  << getOpcodeBytes(memEA, 5) << std::endl;
    
    if (tainter->isTainted(memEA)) {
        *isAnyTainted = true;
    }
    
}

void InstrumentHelper::analyseMem(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TA_UINT memEA, short immSize, TInst* tinst, bool* isAnyTainted) {
    
    
    for (int i = 0; i < immSize; i++)
        if (tainter->isTainted(memEA + i)) {
            *isAnyTainted = true;
            break;
        }
}

void InstrumentHelper::analyseReg(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, REG reg, TInst* tinst, bool* isAnyTainted) {
    RegId tmpReg;
    RegPart tmpPart;
    
    
    tmpReg = Registers::parsePINReg(reg, &tmpPart);
    
    if (tainter->isTainted(tmpReg, tmpPart))  {
        *isAnyTainted = true;
    }
}

void InstrumentHelper::processTInst(const CONTEXT *ctxt, InsData *insData, Tainter *tainter, TInst* tinst, bool* isAnyTainted) {
    
    
    if (*isAnyTainted) {
        if (TA_DEBUG == 3) {
            cout << getOpcodeStr(insData->addr, insData->size) << endl;
            printInfo(insData, tainter);
        } else if (TA_DEBUG == 6) {
            printFormatted(insData, tainter);
        }
    }
}

string InstrumentHelper::getOpcodeBytes(TA_UINT addr, short size) {
    std::stringstream ss;
    
    for (short j = 0; j < size; j++) {
        ss << setfill('0') << setw(2) << hex << (((unsigned int) *(unsigned char*)(addr + j)) & 0xFF);
    }
    
    return ss.str();
}

string InstrumentHelper::getOpcodeStr(TA_UINT addr, short size) {
    std::stringstream ss;
    
    for (short j = 0; j < size; j++) {
        ss << "\\x" << setfill('0') << setw(2) << hex << (((unsigned int) *(unsigned char*)(addr + j)) & 0xFF);
    }
    
    return ss.str();
}

void InstrumentHelper::clearRegs(const CONTEXT *ctxt, Tainter *tainter) {
    tainter->untaint(R_RAX, R_TA_QWORD);
    tainter->untaint(R_RCX, R_TA_QWORD);
    tainter->untaint(R_RDX, R_TA_QWORD);
    tainter->untaint(R_R8, R_TA_QWORD);
    tainter->untaint(R_R9, R_TA_QWORD);
    tainter->untaint(R_R10, R_TA_QWORD);
    tainter->untaint(R_R11, R_TA_QWORD);
}



