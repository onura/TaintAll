//
//  Registers.cpp
//  TaintAll
//
//  Created by Onur on 09/12/15.
//  Copyright © 2015 taintall. All rights reserved.
//

#include "Registers.hpp"
#include <iostream>



std::string Registers::getRegName(RegId reg, RegPart rp) {
    switch (reg) {
        case R_RAX:
            switch (rp) {
                case R_LOW: return "R_AL";
                case R_HIGH: return "R_AH";
                case R_TA_WORD: return "R_AX";
                case R_TA_DWORD: return "R_EAX";
                case R_TA_QWORD: return "R_RAX";
                default: return "R_NONE";
            }
        case R_RBX:
            switch (rp) {
                case R_LOW: return "R_BL";
                case R_HIGH: return "R_BH";
                case R_TA_WORD: return "R_BX";
                case R_TA_DWORD: return "R_EBX";
                case R_TA_QWORD: return "R_RBX";
                default: return "R_NONE";
            }
        case R_RCX:
            switch (rp) {
                case R_LOW: return "R_CL";
                case R_HIGH: return "R_CH";
                case R_TA_WORD: return "R_CX";
                case R_TA_DWORD: return "R_ECX";
                case R_TA_QWORD: return "R_RCX";
                default: return "R_NONE";
            }
        case R_RDX:
            switch (rp) {
                case R_LOW: return "R_DL";
                case R_HIGH: return "R_DH";
                case R_TA_WORD: return "R_DX";
                case R_TA_DWORD: return "R_EDX";
                case R_TA_QWORD: return "R_RDX";
                default: return "R_NONE";
            }
        case R_RDI:
            switch (rp) {
                case R_LOW: return "R_DIL";
                case R_TA_WORD: return "R_DI";
                case R_TA_DWORD: return "R_EDI";
                case R_TA_QWORD: return "R_RDI";
                default: return "R_NONE";
            }
        case R_RSI:
            switch (rp) {
                case R_LOW: return "R_SIL";
                case R_TA_WORD: return "R_SI";
                case R_TA_DWORD: return "R_ESI";
                case R_TA_QWORD: return "R_RSI";
                default: return "R_NONE";
            }
        case R_RBP:
            switch (rp) {
                case R_TA_WORD: return "R_BP";
                case R_TA_DWORD: return "R_EBP";
                case R_TA_QWORD: return "R_RBP";
                default: return "R_NONE";
            }
        case R_RSP:
            switch (rp) {
                case R_TA_WORD: return "R_SP";
                case R_TA_DWORD: return "R_ESP";
                case R_TA_QWORD: return "R_RSP";
                default: return "R_NONE";
            }
        case R_RIP:
            switch (rp) {
                case R_TA_WORD: return "R_IP";
                case R_TA_DWORD: return "R_EIP";
                case R_TA_QWORD: return "R_RIP";
                default: return "R_NONE";
            }
        case R_R8:
            switch (rp) {
                case R_TA_QWORD: return "R_R8";
                default: return "R_NONE";
            }
        case R_R9:
            switch (rp) {
                case R_TA_QWORD: return "R_R9";
                default: return "R_NONE";
            }
        case R_R10:
            switch (rp) {
                case R_TA_QWORD: return "R_R10";
                default: return "R_NONE";
            }
        case R_R11:
            switch (rp) {
                case R_TA_QWORD: return "R_R11";
                default: return "R_NONE";
            }
        case R_R12:
            switch (rp) {
                case R_TA_QWORD: return "R_R12";
                default: return "R_NONE";
            }
        case R_R13:
            switch (rp) {
                case R_TA_QWORD: return "R_R13";
                default: return "R_NONE";
            }
        case R_R14:
            switch (rp) {
                case R_TA_QWORD: return "R_R14";
                default: return "R_NONE";
            }
        case R_R15:
            switch (rp) {
                case R_TA_QWORD: return "R_R15";
                default: return "R_NONE";
            }
        case R_RFLAGS:
            switch (rp) {
                case R_TA_DWORD: return "R_EFLAGS";
                case R_TA_QWORD: return "R_RFLAGS";
                default: return "R_NONE";
            }
        case R_XMM0:
            return "R_XMM0";
        case R_XMM1:
           return "R_XMM1";
        case R_XMM2:
            return "R_XMM2";
        case R_XMM3:
            return "R_XMM3";
        case R_XMM4:
            return "R_XMM4";
        case R_XMM5:
            return "R_XMM5";
        case R_XMM6:
            return "R_XMM6";
        case R_XMM7:
            return "R_XMM7";
        case R_XMM8:
            return "R_XMM8";
        case R_XMM9:
            return "R_XMM9";
        case R_XMM10:
            return "R_XMM10";
        case R_XMM11:
            return "R_XMM11";
        case R_XMM12:
            return "R_XMM12";
        case R_XMM13:
            return "R_XMM13";
        case R_XMM14:
            return "R_XMM14";
        case R_XMM15:
            return "R_XMM15";
        case R_YMM0:
            return "R_YMM0";
        case R_YMM1:
            return "R_YMM1";
        case R_YMM2:
            return "R_YMM2";
        case R_YMM3:
            return "R_YMM3";
        case R_YMM4:
            return "R_YMM4";
        case R_YMM5:
            return "R_YMM5";
        case R_YMM6:
            return "R_YMM6";
        case R_YMM7:
            return "R_YMM7";
        case R_YMM8:
            return "R_YMM8";
        case R_YMM9:
            return "R_YMM9";
        case R_YMM10:
            return "R_YMM10";
        case R_YMM11:
            return "R_YMM11";
        case R_YMM12:
            return "R_YMM12";
        case R_YMM13:
            return "R_YMM13";
        case R_YMM14:
            return "R_YMM14";
        case R_YMM15:
            return "R_YMM15";
        default:
            return "R_NONE";
    }
}

RegPart Registers::getRegPartBySize(short val) {
    if (val == 0) return R_LOW;
    if (val == TA_BYTE) return R_HIGH;
    if (val < TA_WORD) return R_TA_WORD;
    if (val < TA_DWORD) return R_TA_DWORD;
    if (val < TA_QWORD) return R_TA_QWORD;
    if (val < TA_OWORD) return R_TA_OWORD;
    if (val < TA_YWORD) return R_TA_YWORD;
    
    return RP_NONE;
}

RegPart Registers::getRegPartByOrdinal(short ordinal) {
    switch (ordinal) {
        case 0: return R_LOW;
        case 1: return R_HIGH;
        case 2: return R_TA_WORD;
        case 3: return R_TA_DWORD;
        case 4: return R_TA_QWORD;
        case 5: return R_TA_OWORD;
        case 6: return R_TA_YWORD;
        default: return RP_NONE;
    }
}

short Registers::getRegPartOrder(RegPart rp) {
    switch (rp) {
        case R_LOW: return 0;
        case R_HIGH: return 1;
        case R_TA_WORD: return 2;
        case R_TA_DWORD: return 3;
        case R_TA_QWORD: return 4;
        case R_TA_OWORD: return 5;
        default: return 6;
    }
}


void Registers::printTaintedRegs(bool regList[R_END][R_TA_OWORD]) {
    std::string regName;
    
    for (short i = 0; i < R_END; i++)
        for (short j = 0; j < R_TA_OWORD; j++)
            if (regList[i][j]) {
                for (short rp = getRegPartOrder(getRegPartBySize(j)); rp < RP_SIZE; rp++) {
                    /* exception for R_HIGH registers */
                    if (getRegPartByOrdinal(rp) == R_HIGH && !regList[i][getRegPartByOrdinal(rp)])
                        continue;

                    regName = getRegName(RegId(i), getRegPartByOrdinal(rp));
                    if (regName.compare("R_NONE") != 0)
                        std::cout << regName << std::endl;
                    if (regName.find("R_XMM") != std::string::npos)
                        break;
                }
                break;
            }
}

void Registers::printTaintedRegs(bool regList[R_END][R_TA_OWORD], std::ofstream* rFile) {
    std::string regName;
    
    for (short i = 0; i < R_END; i++)
        for (short j = 0; j < R_TA_OWORD; j++)
            if (regList[i][j]) {
                for (short rp = getRegPartOrder(getRegPartBySize(j)); rp < RP_SIZE; rp++) {
                    /* exception for R_HIGH registers */
                    if (getRegPartByOrdinal(rp) == R_HIGH && !regList[i][getRegPartByOrdinal(rp)])
                        continue;
                    
                    regName = getRegName(RegId(i), getRegPartByOrdinal(rp));
                    if (regName.compare("R_NONE") != 0)
                        *rFile << regName << ":";
                    if (regName.find("R_XMM") != std::string::npos)
                        break;
                }
                break;
            }
}

RegId Registers::parsePINReg(REG pinReg, RegPart * regPart) {
    
    switch (pinReg) {
        case REG_RAX: *regPart = R_TA_QWORD; return R_RAX;
        case REG_EAX: *regPart = R_TA_DWORD; return R_RAX;
        case REG_AX: *regPart = R_TA_WORD; return R_RAX;
        case REG_AH: *regPart = R_HIGH; return R_RAX;
        case REG_AL: *regPart = R_LOW; return R_RAX;
            
        case REG_RBX: *regPart = R_TA_QWORD; return R_RBX;
        case REG_EBX: *regPart = R_TA_DWORD; return R_RBX;
        case REG_BX: *regPart = R_TA_WORD; return R_RBX;
        case REG_BH: *regPart = R_HIGH; return R_RBX;
        case REG_BL: *regPart = R_LOW; return R_RBX;
            
        case REG_RCX: *regPart = R_TA_QWORD; return R_RCX;
        case REG_ECX: *regPart = R_TA_DWORD; return R_RCX;
        case REG_CX: *regPart = R_TA_WORD; return R_RCX;
        case REG_CH: *regPart = R_HIGH; return R_RCX;
        case REG_CL: *regPart = R_LOW; return R_RCX;
            
        case REG_RDX: *regPart = R_TA_QWORD; return R_RDX;
        case REG_EDX: *regPart = R_TA_DWORD; return R_RDX;
        case REG_DX: *regPart = R_TA_WORD; return R_RDX;
        case REG_DH: *regPart = R_HIGH; return R_RDX;
        case REG_DL: *regPart = R_LOW; return R_RDX;
        
        case REG_RDI: *regPart = R_TA_QWORD; return R_RDI;
        case REG_EDI: *regPart = R_TA_DWORD; return R_RDI;
        case REG_DI: *regPart = R_TA_WORD; return R_RDI;
        case REG_DIL: *regPart = R_LOW; return R_RDI;
        
        case REG_RSI: *regPart = R_TA_QWORD; return R_RSI;
        case REG_ESI: *regPart = R_TA_DWORD; return R_RSI;
        case REG_SI: *regPart = R_TA_WORD; return R_RSI;
        case REG_SIL: *regPart = R_LOW; return R_RSI;
            
        case REG_RBP: *regPart = R_TA_QWORD; return R_RBP;
        case REG_EBP: *regPart = R_TA_DWORD; return R_RBP;
        case REG_BP: *regPart = R_TA_WORD; return R_RBP;
        case REG_BPL: *regPart = R_LOW; return R_RBP;
            
        case REG_RSP: *regPart = R_TA_QWORD; return R_RSP;
        case REG_ESP: *regPart = R_TA_DWORD; return R_RSP;
        case REG_SP: *regPart = R_TA_WORD; return R_RSP;
        case REG_SPL: *regPart = R_LOW; return R_RSP;

        case REG_R8: *regPart = R_TA_QWORD; return R_R8;
        case REG_R8D: *regPart = R_TA_DWORD; return R_R8;
        case REG_R8W: *regPart = R_TA_WORD; return R_R8;
        case REG_R8B: *regPart = R_LOW; return R_R8;
            
        case REG_R9: *regPart = R_TA_QWORD; return R_R9;
        case REG_R9D: *regPart = R_TA_DWORD; return R_R9;
        case REG_R9W: *regPart = R_TA_WORD; return R_R9;
        case REG_R9B: *regPart = R_LOW; return R_R9;
        
        case REG_R10: *regPart = R_TA_QWORD; return R_R10;
        case REG_R10D: *regPart = R_TA_DWORD; return R_R10;
        case REG_R10W: *regPart = R_TA_WORD; return R_R10;
        case REG_R10B: *regPart = R_LOW; return R_R10;
        
        case REG_R11: *regPart = R_TA_QWORD; return R_R11;
        case REG_R11D: *regPart = R_TA_DWORD; return R_R11;
        case REG_R11W: *regPart = R_TA_WORD; return R_R11;
        case REG_R11B: *regPart = R_LOW; return R_R11;
            
        case REG_R12: *regPart = R_TA_QWORD; return R_R12;
        case REG_R12D: *regPart = R_TA_DWORD; return R_R12;
        case REG_R12W: *regPart = R_TA_WORD; return R_R12;
        case REG_R12B: *regPart = R_LOW; return R_R12;
        
        case REG_R13: *regPart = R_TA_QWORD; return R_R13;
        case REG_R13D: *regPart = R_TA_DWORD; return R_R13;
        case REG_R13W: *regPart = R_TA_WORD; return R_R13;
        case REG_R13B: *regPart = R_LOW; return R_R13;

        case REG_R14: *regPart = R_TA_QWORD; return R_R14;
        case REG_R14D: *regPart = R_TA_DWORD; return R_R14;
        case REG_R14W: *regPart = R_TA_WORD; return R_R14;
        case REG_R14B: *regPart = R_LOW; return R_R14;

        case REG_R15: *regPart = R_TA_QWORD; return R_R15;
        case REG_R15D: *regPart = R_TA_DWORD; return R_R15;
        case REG_R15W: *regPart = R_TA_WORD; return R_R15;
        case REG_R15B: *regPart = R_LOW; return R_R15;

        case REG_RFLAGS: *regPart = R_TA_QWORD; return R_RFLAGS;
        case REG_EFLAGS: *regPart = R_TA_DWORD; return R_RFLAGS;
            
        case REG_RIP: *regPart = R_TA_QWORD; return R_RIP;
        case REG_EIP: *regPart = R_TA_DWORD; return R_RIP;
            
        case REG_XMM0: *regPart = R_TA_OWORD; return R_XMM0;
        case REG_XMM1: *regPart = R_TA_OWORD; return R_XMM1;
        case REG_XMM2: *regPart = R_TA_OWORD; return R_XMM2;
        case REG_XMM3: *regPart = R_TA_OWORD; return R_XMM3;
        case REG_XMM4: *regPart = R_TA_OWORD; return R_XMM4;
        case REG_XMM5: *regPart = R_TA_OWORD; return R_XMM5;
        case REG_XMM6: *regPart = R_TA_OWORD; return R_XMM6;
        case REG_XMM7: *regPart = R_TA_OWORD; return R_XMM7;
        case REG_XMM8: *regPart = R_TA_OWORD; return R_XMM8;
        case REG_XMM9: *regPart = R_TA_OWORD; return R_XMM9;
        case REG_XMM10: *regPart = R_TA_OWORD; return R_XMM10;
        case REG_XMM11: *regPart = R_TA_OWORD; return R_XMM11;
        case REG_XMM12: *regPart = R_TA_OWORD; return R_XMM12;
        case REG_XMM13: *regPart = R_TA_OWORD; return R_XMM13;
        case REG_XMM14: *regPart = R_TA_OWORD; return R_XMM14;
        case REG_XMM15: *regPart = R_TA_OWORD; return R_XMM15;
            
        case REG_YMM0: *regPart = R_TA_YWORD; return R_YMM0;
        case REG_YMM1: *regPart = R_TA_YWORD; return R_YMM1;
        case REG_YMM2: *regPart = R_TA_YWORD; return R_YMM2;
        case REG_YMM3: *regPart = R_TA_YWORD; return R_YMM3;
        case REG_YMM4: *regPart = R_TA_YWORD; return R_YMM4;
        case REG_YMM5: *regPart = R_TA_YWORD; return R_YMM5;
        case REG_YMM6: *regPart = R_TA_YWORD; return R_YMM6;
        case REG_YMM7: *regPart = R_TA_YWORD; return R_YMM7;
        case REG_YMM8: *regPart = R_TA_YWORD; return R_YMM8;
        case REG_YMM9: *regPart = R_TA_YWORD; return R_YMM9;
        case REG_YMM10: *regPart = R_TA_YWORD; return R_YMM10;
        case REG_YMM11: *regPart = R_TA_YWORD; return R_YMM11;
        case REG_YMM12: *regPart = R_TA_YWORD; return R_YMM12;
        case REG_YMM13: *regPart = R_TA_YWORD; return R_YMM13;
        case REG_YMM14: *regPart = R_TA_YWORD; return R_YMM14;
        case REG_YMM15: *regPart = R_TA_YWORD; return R_YMM15;
            
        default:
            return R_END;
    }
}

REG Registers::convertPINReg(RegId reg) {
    
    switch (reg) {
        case R_RAX: return REG_RAX;
        case R_RBX: return REG_RBX;
        case R_RCX: return REG_RCX;
        case R_RDX: return REG_RDX;
        case R_RDI: return REG_RDI;
        case R_RSI: return REG_RSI;
        case R_RBP: return REG_RBP;
        case R_RSP: return REG_RSP;
        case R_R8: return REG_R8;
        case R_R9: return REG_R9;
        case R_R10: return REG_R10;
        case R_R11: return REG_R11;
        case R_R12: return REG_R12;
        case R_R13: return REG_R13;
        case R_R14: return REG_R14;
        case R_R15: return REG_R15;
        default:
            return REG_INVALID_;
    }
}


