//
//  registers.hpp
//  
//
//  Created by Onur on 07/12/15.
//
//

#include "ta_types.hpp"
#include <map>
#include <string>
#include "pin.H"
#include <fstream>


#ifndef registers_h
#define registers_h

#define GET_REGSIZE(reg) regSizes[reg]

//enum for x86_64 registers
enum RegId {
    R_RAX,
    R_RBX,
    R_RCX,
    R_RDX,
    R_RDI,
    R_RSI,
    R_RBP,
    R_RSP,
    R_RIP,
    R_R8,
    R_R9,
    R_R10,
    R_R11,
    R_R12,
    R_R13,
    R_R14,
    R_R15,
    R_XMM0,
    R_XMM1,
    R_XMM2,
    R_XMM3,
    R_XMM4,
    R_XMM5,
    R_XMM6,
    R_XMM7,
    R_XMM8,
    R_XMM9,
    R_XMM10,
    R_XMM11,
    R_XMM12,
    R_XMM13,
    R_XMM14,
    R_XMM15,
    R_RFLAGS,
    R_YMM0,
    R_YMM1,
    R_YMM2,
    R_YMM3,
    R_YMM4,
    R_YMM5,
    R_YMM6,
    R_YMM7,
    R_YMM8,
    R_YMM9,
    R_YMM10,
    R_YMM11,
    R_YMM12,
    R_YMM13,
    R_YMM14,
    R_YMM15,
    R_END
};


//registers sizes in bytes
const short regSizes[] = {
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_QWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_OWORD,
    TA_QWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    TA_YWORD,
    0
};

//cpu flags
enum RegFlags {
    R_AF,
    R_CF,
    R_DF,
    R_IF,
    R_OF,
    R_PF,
    R_SF,
    R_TF,
    R_ZF
};

//x86_64 Reg Parts
enum RegPart {
    R_LOW = 0,
    R_HIGH = 1,
    R_TA_WORD = 2,
    R_TA_DWORD = 4,
    R_TA_QWORD = 8,
    R_TA_OWORD = 16,
    R_TA_YWORD = 32,
    RP_SIZE = 8,
    RP_NONE = 17
};

class Registers {
public:
    static std::string getRegName(RegId reg, RegPart regPart);
    static void printTaintedRegs(bool regList[R_END][R_TA_OWORD]);
    static void printTaintedRegs(bool regList[R_END][R_TA_OWORD], std::ofstream* rfile);
    static RegPart getRegPartBySize(short val);
    static RegPart getRegPartByOrdinal(short ordinal);
    static short getRegPartOrder(RegPart rp);
    static RegId parsePINReg(REG pinReg, RegPart * regPart);
    static REG convertPINReg(RegId reg);
};

#endif /* registers_h */
