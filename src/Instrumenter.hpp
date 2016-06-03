//
//  Instrumenter.hpp
//  TaintAll
//
//  Created by Onur on 15/12/15.
//  Copyright © 2015 taintall. All rights reserved.
//

#ifndef Instrumenter_hpp
#define Instrumenter_hpp

#include "Registers.hpp"
#include "Tainter.hpp"
#include "InstrumentHelper.hpp"
#include "pin.H"
#include <list>


class TAddr {
public:
    TA_UINT instAddr;
    TA_UINT memAddr;
    TA_UINT msize;
};

class TReg {
public:
    TA_UINT instAddr;
    RegId reg;
    RegPart rp;
};

class TPtr {
public:
    TA_UINT instAddr;
    RegId reg;
    TA_UINT msize;
};

class IMGInfo {
public:
    TA_UINT imageBase;
    TA_UINT staticImageBase;
    TA_UINT pieIter;
};

class readSysCall {
public:
    TA_UINT memAddr;
    TA_UINT size;
};

class UserCommands {
public:
    TA_UINT startTaint;
    TA_UINT stopTaint;
};



class Instrumenter {
public:
    /* instrumentation functions */
    static void insInstFunc(INS ins, void *v);
    static void imgInstFunc(IMG img, void *v);
    static void sysCallInstFunc(THREADID thread_id, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v);
    static void sysCallExitInstFunc(THREADID thread_id, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v);
    static void programFinFunc(int code, void *v);
    static bool init(int argc, char** argv);
    static void clean();
    
    static void runProgram();
    static std::string getRelativeAddr(TA_UINT virtualAddr, TA_UINT baseAddr);
    static void setStaticImageBase(TA_UINT);
    static void startAt(TA_UINT addr);
    static void stopAt(TA_UINT addr);
  
    /* taint - untaint functions */
    static void taintAtAddr(TA_UINT instAddr, TA_UINT memAddr, TA_UINT msize);
    static void taintAtAddr(TA_UINT instAddr, RegId reg, RegPart rp);
    static void unTaintAtAddr(TA_UINT instAddr, TA_UINT memAddr, TA_UINT msize);
    static void unTaintAtAddr(TA_UINT instAddr, RegId reg, RegPart rp);
    static void taintAtAddr(TA_UINT instAddr, RegId reg, TA_UINT msize);
    static void unTaintAtAddr(TA_UINT instAddr, RegId reg, TA_UINT msize);
    
private:
    //Attributes
    static Tainter tainter;
    static std::list<TAddr> addrsToBeTainted;
    static std::list<TReg> regsToBeTainted;
    static std::list<TAddr> addrsToBeUntainted;
    static std::list<TReg> regsToBeUntainted;
    static std::list<TPtr> pointersToBeTainted;
    static std::list<TPtr> pointersToBeUntainted;

    static std::ofstream resultFile;

    
    static IMGInfo imgInfo;
    static readSysCall lastReadSysCall;
    static bool isEngineRunning;
    static UserCommands usrCmd;
    static bool isSERunning;
    static bool isRegsCleared;
    
    //methods
    static void checkToBeInst(const CONTEXT* ctxt, TA_UINT instAddr);
    static void parseCmdLine();

};


#endif /* Instrumenter_hpp */
