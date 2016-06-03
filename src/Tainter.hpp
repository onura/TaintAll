//
//  tainter.h
//  
//
//  Created by Onur on 09/12/15.
//
//

#ifndef tainter_h
#define tainter_h

#include "Registers.hpp"
#include "ta_types.hpp"
#include <list>
#include <iostream>


class Tainter {
private:
    //attributes
    std::list<TA_UINT> taintedAddrs;
    bool taintedRegs[R_END][TA_YWORD];
    void taintRegInner(RegId reg, RegPart rp, bool val);
    
public:
    //constructors
    Tainter();
    
    //methods
    void taint(TA_UINT addr);
    void taint(RegId reg, RegPart rp);
    void taint(TA_UINT addr, TA_UINT msize);
    void untaint(TA_UINT addr);
    void untaint(RegId reg, RegPart rp);
    void untaint(TA_UINT addr, TA_UINT msize);
    bool isTainted(TA_UINT addr);
    bool isTainted(RegId reg, RegPart rp);
    void cleanAll();
    void spreadTaintMI(TA_UINT addr, TA_UINT wsize);
    void spreadTaintMR(TA_UINT addr, RegId reg, RegPart rp);
    void spreadTaintRI(RegId reg, RegPart rp);
    void spreadTaintRM(RegId reg, RegPart rp, TA_UINT addr);
    void spreadTaintRR(RegId dstReg, RegPart dstRp, RegId srcReg, RegPart srcRp);
    void spreadTaintMM(TA_UINT dstAddr, TA_UINT srcAddr, TA_UINT dataSize);
    void getTaintedRegs(bool regList[R_END][R_TA_OWORD]);
    std::list<TA_UINT> getTaintedMem(TA_UINT begin, TA_UINT end);
    std::list<TA_UINT> getTaintedMem();
};


#endif /* tainter_h */
