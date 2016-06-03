//
//  tainter.cpp
//  
//
//  Created by Onur on 09/12/15.
//
//

#include "Tainter.hpp"



Tainter::Tainter() {
    cleanAll();
}

void Tainter::cleanAll() {
    taintedAddrs.empty();
    
    for (short i = 0; i < R_END; i++)
        for (short j = 0; j < R_TA_OWORD; j++)
            taintedRegs[i][j] = false;
}

void Tainter::taint(TA_UINT addr) {
    if (!isTainted(addr))
        taintedAddrs.push_back(addr);
}

void Tainter::taint(TA_UINT addr, TA_UINT msize) {
    for (TA_UINT i = addr; i < addr + msize; i++)
        taint(i);
}

void Tainter::untaint(TA_UINT addr) {
    if (isTainted(addr))
        taintedAddrs.remove(addr);
}

void Tainter::untaint(TA_UINT addr, TA_UINT msize) {
    for (TA_UINT i = addr; i < addr + msize; i++)
        untaint(i);
}

bool Tainter::isTainted(TA_UINT addr) {
    std::list<TA_UINT>::iterator found = find(taintedAddrs.begin(), taintedAddrs.end(), addr);
    
    return (found != taintedAddrs.end());
}

//Taint a register by name
void Tainter::taint(RegId reg, RegPart rp) {
    taintRegInner(reg, rp, true);
}

//Untaint a register by name
void Tainter::untaint(RegId reg, RegPart rp) {
    taintRegInner(reg, rp, false);
}

void Tainter::taintRegInner(RegId reg, RegPart rp, bool val) {
    if (rp == R_LOW || rp == R_HIGH)
        taintedRegs[reg][rp] = val;
    else
        for (short i = 0; i < rp; i++)
            taintedRegs[reg][i] = val;
}


bool Tainter::isTainted(RegId reg, RegPart rp) {
    if (rp == R_LOW || rp == R_HIGH)
        return taintedRegs[reg][rp];
    else {
        for (short i = 0; i < rp; i++)
            if (taintedRegs[reg][i])
                return true;
        return false;
    }
}


//Immediate to Memory spreading
void Tainter::spreadTaintMI(TA_UINT addr, TA_UINT wsize) {
    for (TA_UINT i = addr; i < addr + wsize; i++)
        untaint(i);
}

//Register to Memory spreading
void Tainter::spreadTaintMR(TA_UINT addr, RegId reg, RegPart rp) {
    if (rp == R_LOW || rp == R_HIGH) {
        if (taintedRegs[reg][rp])
            taint(addr);
        else
            untaint(addr);
    } else {
        for (short i = 0; i < rp; i++)
            if (taintedRegs[reg][i])
                taint(addr + i);
            else
                untaint(addr + i);
    }
}

//Immediate to Register spreading
void Tainter::spreadTaintRI(RegId reg, RegPart rp) {
    untaint(reg, rp);
}

//Memory to Register Spreading
void Tainter::spreadTaintRM(RegId reg, RegPart rp, TA_UINT addr) {
    if (rp == R_LOW || rp == R_HIGH)
        taintedRegs[reg][rp] = isTainted(addr);
    else
        for (short i = 0; i < rp; i++)
            taintedRegs[reg][i] = isTainted(addr + i);
}

//Register to Register Spreading
void Tainter::spreadTaintRR(RegId dstReg, RegPart dstRp, RegId srcReg, RegPart srcRp) {
    if ((dstRp == R_LOW || dstRp == R_HIGH) && (srcRp == R_LOW || srcRp == R_HIGH))
        taintedRegs[dstReg][dstRp] = taintedRegs[srcReg][srcRp];
    else
        for (short i = 0; i < dstRp; i++)
            taintedRegs[dstReg][i] = taintedRegs[srcReg][i];
}

//Memory to Memory spreading
void Tainter::spreadTaintMM(TA_UINT dstAddr, TA_UINT srcAddr, TA_UINT dataSize) {
    for (TA_UINT i = 0 ; i < dataSize; i++)
        if (isTainted(srcAddr + i))
            taint(dstAddr + i);
        else
            untaint(dstAddr + i);
}

void Tainter::getTaintedRegs(bool regList[R_END][R_TA_OWORD]) {
    for (short i = 0; i < R_END; i++)
        for (short j = 0; j < R_TA_OWORD; j++)
            regList[i][j] = taintedRegs[i][j];
}


std::list<TA_UINT> Tainter::getTaintedMem(TA_UINT begin, TA_UINT end) {
    std::list<TA_UINT> memlist;
    
    for (TA_UINT i = 0; i < end; i++)
        if (isTainted(i))
            memlist.push_back(i);
    
    memlist.sort();
    return memlist;
}

std::list<TA_UINT> Tainter::getTaintedMem() {
    std::list<TA_UINT> memlist;
    
    for (std::list<TA_UINT>::iterator iter = taintedAddrs.begin(); iter != taintedAddrs.end(); iter++) {
        memlist.push_back(*iter);
    }

    memlist.sort();
    return memlist;
}

